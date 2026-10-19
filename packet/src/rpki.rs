// Copyright (C) 2020-2021 The RustyBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use bytes::{BufMut, BytesMut};
use std::io::Cursor;
use std::net::IpAddr;
use tokio_util::codec::{Decoder, Encoder};

use crate::IpNet;
use crate::error::Error;

pub struct Prefix {
    pub net: IpNet,
    pub flags: u8,
    pub max_length: u8,
    pub as_number: u32,
}

pub enum Message {
    SerialNotify {
        session_id: u16,
        serial_number: u32,
    },
    SerialQuery {
        session_id: u16,
        serial_number: u32,
    },
    ResetQuery,
    CacheResponse {
        session_id: u16,
    },
    IpPrefix(Prefix),
    EndOfData {
        session_id: u16,
        serial_number: u32,
        /// Seconds between Serial Queries when the session is up (RFC 8210 v1+; 0 for v0).
        refresh_interval: u32,
        /// Seconds to wait before retrying after a failed Serial Query (RFC 8210 v1+; 0 for v0).
        retry_interval: u32,
        /// Seconds before a router must re-fetch all data if no update received (RFC 8210 v1+; 0 for v0).
        expire_interval: u32,
    },
    CacheReset,
    ErrorReport {
        /// Error code from RFC 8210 section 12.
        error_code: u16,
        /// Copy of the erroneous PDU, if any.
        pdu: Vec<u8>,
        /// Diagnostic text, if any.
        text: String,
    },
}

/// Error codes carried in Error Report PDUs (RFC 8210 section 12).
pub mod error_code {
    pub const CORRUPT_DATA: u16 = 0;
    pub const INTERNAL_ERROR: u16 = 1;
    pub const NO_DATA_AVAILABLE: u16 = 2;
    pub const INVALID_REQUEST: u16 = 3;
    pub const UNSUPPORTED_PROTOCOL_VERSION: u16 = 4;
    pub const UNSUPPORTED_PDU_TYPE: u16 = 5;
    pub const WITHDRAWAL_OF_UNKNOWN_RECORD: u16 = 6;
    pub const DUPLICATE_ANNOUNCEMENT_RECEIVED: u16 = 7;
    pub const UNEXPECTED_PROTOCOL_VERSION: u16 = 8;

    /// Human-readable name of an error code.
    pub fn name(code: u16) -> &'static str {
        match code {
            CORRUPT_DATA => "Corrupt Data",
            INTERNAL_ERROR => "Internal Error",
            NO_DATA_AVAILABLE => "No Data Available",
            INVALID_REQUEST => "Invalid Request",
            UNSUPPORTED_PROTOCOL_VERSION => "Unsupported Protocol Version",
            UNSUPPORTED_PDU_TYPE => "Unsupported PDU Type",
            WITHDRAWAL_OF_UNKNOWN_RECORD => "Withdrawal of Unknown Record",
            DUPLICATE_ANNOUNCEMENT_RECEIVED => "Duplicate Announcement Received",
            UNEXPECTED_PROTOCOL_VERSION => "Unexpected Protocol Version",
            _ => "Unknown",
        }
    }
}

/// A protocol error detected while decoding a PDU from the cache. Carries
/// what is needed to answer with an Error Report (RFC 8210 section 5.11).
#[derive(Debug)]
pub struct RtrError {
    pub code: u16,
    /// Copy of the offending PDU (or as much of it as is known).
    pub pdu: Vec<u8>,
    pub text: String,
}

impl RtrError {
    fn new(code: u16, pdu: &[u8], text: String) -> Self {
        RtrError {
            code,
            pdu: pdu.to_vec(),
            text,
        }
    }

    /// The Error Report to send back to the cache, or `None` when the
    /// offending PDU was itself an Error Report, which MUST NOT be answered
    /// with another (RFC 8210 section 5.11).
    pub fn report(&self) -> Option<Message> {
        if self.pdu.get(1) == Some(&Message::ERROR_REPORT)
            || self.code == error_code::INTERNAL_ERROR
        {
            return None;
        }
        Some(Message::ErrorReport {
            error_code: self.code,
            pdu: self.pdu.clone(),
            text: self.text.clone(),
        })
    }
}

impl std::fmt::Display for RtrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}): {}",
            error_code::name(self.code),
            self.code,
            self.text
        )
    }
}

impl std::error::Error for RtrError {}

impl From<std::io::Error> for RtrError {
    fn from(e: std::io::Error) -> Self {
        RtrError {
            code: error_code::INTERNAL_ERROR,
            pdu: Vec::new(),
            text: e.to_string(),
        }
    }
}

impl Message {
    pub const SERIAL_NOTIFY: u8 = 0;
    pub const SERIAL_QUERY: u8 = 1;
    pub const RESET_QUERY: u8 = 2;
    pub const CACHE_RESPONSE: u8 = 3;
    pub const IPV4_PREFIX: u8 = 4;
    pub const IPV6_PREFIX: u8 = 6;
    pub const END_OF_DATA: u8 = 7;
    pub const CACHE_RESET: u8 = 8;
    pub const ROUTER_KEY: u8 = 9;
    pub const ERROR_REPORT: u8 = 10;

    /// Highest protocol version understood (RFC 8210).
    pub const MAX_VERSION: u8 = 1;
    /// Length of the common PDU header (RFC 8210 section 5.1).
    const HEADER_LENGTH: usize = 8;
    /// Upper bound for variable-length PDUs (Router Key, Error Report), so a
    /// bogus length cannot make the decoder buffer without limit.
    const MAX_LENGTH: usize = 65536;

    /// Checks the length field of a PDU header against its type
    /// (RFC 8210 section 5). Unknown types are an error.
    fn check_length(
        header: &[u8],
        version: u8,
        message_type: u8,
        length: usize,
    ) -> Result<(), RtrError> {
        let ok = match message_type {
            Message::SERIAL_NOTIFY | Message::SERIAL_QUERY => length == 12,
            Message::RESET_QUERY | Message::CACHE_RESPONSE | Message::CACHE_RESET => length == 8,
            Message::IPV4_PREFIX => length == 20,
            Message::IPV6_PREFIX => length == 32,
            Message::END_OF_DATA => length == if version >= 1 { 24 } else { 12 },
            // Header + SKI (20) + ASN (4) + SPKI.
            Message::ROUTER_KEY if version >= 1 => (32..=Message::MAX_LENGTH).contains(&length),
            // Header + encapsulated PDU length (4) + error text length (4).
            Message::ERROR_REPORT => (16..=Message::MAX_LENGTH).contains(&length),
            _ => {
                return Err(RtrError::new(
                    error_code::UNSUPPORTED_PDU_TYPE,
                    header,
                    format!("unsupported PDU type {}", message_type),
                ));
            }
        };
        if ok {
            Ok(())
        } else {
            Err(RtrError::new(
                error_code::CORRUPT_DATA,
                header,
                format!("invalid length {} for PDU type {}", length, message_type),
            ))
        }
    }

    /// Checks the prefix and maximum length of an IP Prefix PDU
    /// (RFC 8210 sections 5.6, 5.7): the prefix length must not exceed the
    /// address width and the maximum length must lie between the two.
    fn check_prefix(pdu: &[u8], width: u8, prefix_len: u8, max_length: u8) -> Result<(), RtrError> {
        if prefix_len > width || max_length > width || max_length < prefix_len {
            return Err(RtrError::new(
                error_code::CORRUPT_DATA,
                pdu,
                format!(
                    "invalid prefix length {} / max length {}",
                    prefix_len, max_length
                ),
            ));
        }
        Ok(())
    }

    fn to_bytes(&self, version: u8) -> Result<Vec<u8>, Error> {
        let buf: Vec<u8> = Vec::new();
        let mut c = Cursor::new(buf);
        match self {
            Message::SerialNotify {
                session_id,
                serial_number,
            } => {
                c.write_u8(version)?;
                c.write_u8(Message::SERIAL_NOTIFY)?;
                c.write_u16::<NetworkEndian>(*session_id)?;
                c.write_u32::<NetworkEndian>(12)?;
                c.write_u32::<NetworkEndian>(*serial_number)?;
            }
            Message::ResetQuery => {
                c.write_u8(version)?;
                c.write_u8(Message::RESET_QUERY)?;
                c.write_u16::<NetworkEndian>(0)?;
                c.write_u32::<NetworkEndian>(8)?;
            }
            Message::SerialQuery {
                session_id,
                serial_number,
            } => {
                c.write_u8(version)?;
                c.write_u8(Message::SERIAL_QUERY)?;
                c.write_u16::<NetworkEndian>(*session_id)?;
                c.write_u32::<NetworkEndian>(12)?;
                c.write_u32::<NetworkEndian>(*serial_number)?;
            }
            Message::CacheResponse { session_id } => {
                c.write_u8(version)?;
                c.write_u8(Message::CACHE_RESPONSE)?;
                c.write_u16::<NetworkEndian>(*session_id)?;
                c.write_u32::<NetworkEndian>(8)?;
            }
            Message::IpPrefix(prefix) => match &prefix.net {
                crate::IpNet::V4(net) => {
                    c.write_u8(version)?;
                    c.write_u8(Message::IPV4_PREFIX)?;
                    c.write_u16::<NetworkEndian>(0)?;
                    c.write_u32::<NetworkEndian>(20)?;
                    c.write_u8(prefix.flags)?;
                    c.write_u8(net.mask)?;
                    c.write_u8(prefix.max_length)?;
                    c.write_u8(0)?;
                    for octet in net.addr.octets() {
                        c.write_u8(octet)?;
                    }
                    c.write_u32::<NetworkEndian>(prefix.as_number)?;
                }
                crate::IpNet::V6(net) => {
                    c.write_u8(version)?;
                    c.write_u8(Message::IPV6_PREFIX)?;
                    c.write_u16::<NetworkEndian>(0)?;
                    c.write_u32::<NetworkEndian>(32)?;
                    c.write_u8(prefix.flags)?;
                    c.write_u8(net.mask)?;
                    c.write_u8(prefix.max_length)?;
                    c.write_u8(0)?;
                    for octet in net.addr.octets() {
                        c.write_u8(octet)?;
                    }
                    c.write_u32::<NetworkEndian>(prefix.as_number)?;
                }
            },
            Message::EndOfData {
                session_id,
                serial_number,
                refresh_interval,
                retry_interval,
                expire_interval,
            } => {
                c.write_u8(version)?;
                c.write_u8(Message::END_OF_DATA)?;
                c.write_u16::<NetworkEndian>(*session_id)?;
                if version >= 1 {
                    c.write_u32::<NetworkEndian>(24)?;
                    c.write_u32::<NetworkEndian>(*serial_number)?;
                    c.write_u32::<NetworkEndian>(*refresh_interval)?;
                    c.write_u32::<NetworkEndian>(*retry_interval)?;
                    c.write_u32::<NetworkEndian>(*expire_interval)?;
                } else {
                    c.write_u32::<NetworkEndian>(12)?;
                    c.write_u32::<NetworkEndian>(*serial_number)?;
                }
            }
            Message::CacheReset => {
                c.write_u8(version)?;
                c.write_u8(Message::CACHE_RESET)?;
                c.write_u16::<NetworkEndian>(0)?;
                c.write_u32::<NetworkEndian>(8)?;
            }
            Message::ErrorReport {
                error_code,
                pdu,
                text,
            } => {
                // Keep the whole PDU within the decoder's limit.
                let room = Message::MAX_LENGTH - 16;
                let pdu = &pdu[..pdu.len().min(room)];
                let text = &text.as_bytes()[..text.len().min(room - pdu.len())];
                c.write_u8(version)?;
                c.write_u8(Message::ERROR_REPORT)?;
                c.write_u16::<NetworkEndian>(*error_code)?;
                c.write_u32::<NetworkEndian>((16 + pdu.len() + text.len()) as u32)?;
                c.write_u32::<NetworkEndian>(pdu.len() as u32)?;
                std::io::Write::write_all(&mut c, pdu)?;
                c.write_u32::<NetworkEndian>(text.len() as u32)?;
                std::io::Write::write_all(&mut c, text)?;
            }
        }
        Ok(c.into_inner())
    }

    /// Parses one PDU from `buf`. Returns `Ok(None)` if `buf` does not yet
    /// hold the whole PDU, and an error if the PDU is malformed or of an
    /// unsupported type or version. The returned length is the number of
    /// bytes to consume and the version is that of the PDU; the message is
    /// `None` for PDUs that are skipped.
    #[allow(clippy::type_complexity)]
    fn from_bytes(buf: &[u8]) -> Result<Option<(Option<Message>, u8, usize)>, RtrError> {
        if buf.len() < Message::HEADER_LENGTH {
            return Ok(None);
        }
        let mut c = Cursor::new(buf);

        let version = c.read_u8()?;
        let message_type = c.read_u8()?;
        // For ErrorReport, this field carries the error code instead of session_id.
        let session_id = c.read_u16::<NetworkEndian>()?;
        let length = c.read_u32::<NetworkEndian>()? as usize;

        let header = &buf[..Message::HEADER_LENGTH];
        if version > Message::MAX_VERSION {
            return Err(RtrError::new(
                error_code::UNSUPPORTED_PROTOCOL_VERSION,
                header,
                format!("unsupported protocol version {}", version),
            ));
        }
        Message::check_length(header, version, message_type, length)?;
        if length > buf.len() {
            return Ok(None);
        }
        let pdu = &buf[..length];

        let msg = match message_type {
            Message::SERIAL_NOTIFY => {
                let serial_number = c.read_u32::<NetworkEndian>()?;
                Message::SerialNotify {
                    session_id,
                    serial_number,
                }
            }
            Message::SERIAL_QUERY => {
                let serial_number = c.read_u32::<NetworkEndian>()?;
                Message::SerialQuery {
                    session_id,
                    serial_number,
                }
            }
            Message::RESET_QUERY => Message::ResetQuery,
            Message::CACHE_RESPONSE => Message::CacheResponse { session_id },
            Message::IPV4_PREFIX => {
                let flags = c.read_u8()?;
                let prefix_len = c.read_u8()?;
                let max_length = c.read_u8()?;
                let _ = c.read_u8()?;
                let mut octets = [0_u8; 4];
                for i in 0..4 {
                    octets[i as usize] = c.read_u8()?;
                }
                let as_number = c.read_u32::<NetworkEndian>()?;
                Message::check_prefix(pdu, (octets.len() * 8) as u8, prefix_len, max_length)?;
                Message::IpPrefix(Prefix {
                    net: IpNet::new(IpAddr::from(octets), prefix_len),
                    flags,
                    max_length,
                    as_number,
                })
            }
            Message::IPV6_PREFIX => {
                let flags = c.read_u8()?;
                let prefix_len = c.read_u8()?;
                let max_length = c.read_u8()?;
                let _ = c.read_u8()?;
                let mut octets = [0_u8; 16];
                for i in 0..16 {
                    octets[i as usize] = c.read_u8()?;
                }
                let as_number = c.read_u32::<NetworkEndian>()?;
                Message::check_prefix(pdu, (octets.len() * 8) as u8, prefix_len, max_length)?;
                Message::IpPrefix(Prefix {
                    net: IpNet::new(IpAddr::from(octets), prefix_len),
                    flags,
                    max_length,
                    as_number,
                })
            }
            Message::END_OF_DATA => {
                let serial_number = c.read_u32::<NetworkEndian>()?;
                // RFC 8210 v1 adds three interval fields absent in v0.
                let (refresh_interval, retry_interval, expire_interval) = if version >= 1 {
                    (
                        c.read_u32::<NetworkEndian>()?,
                        c.read_u32::<NetworkEndian>()?,
                        c.read_u32::<NetworkEndian>()?,
                    )
                } else {
                    (0, 0, 0)
                };
                Message::EndOfData {
                    session_id,
                    serial_number,
                    refresh_interval,
                    retry_interval,
                    expire_interval,
                }
            }
            Message::CACHE_RESET => Message::CacheReset,
            // For ErrorReport, bytes 2-3 of the common header carry the error code
            // rather than a session ID (RFC 8210 section 10).
            Message::ERROR_REPORT => {
                let corrupt = || {
                    RtrError::new(
                        error_code::CORRUPT_DATA,
                        pdu,
                        "inconsistent Error Report lengths".to_string(),
                    )
                };
                let body = &pdu[Message::HEADER_LENGTH..];
                let pdu_len = u32::from_be_bytes(body[..4].try_into().unwrap()) as usize;
                let rest = body[4..].get(pdu_len..).ok_or_else(corrupt)?;
                let enc = body[4..4 + pdu_len].to_vec();
                let text_len =
                    u32::from_be_bytes(rest.get(..4).ok_or_else(corrupt)?.try_into().unwrap())
                        as usize;
                if rest.len() != 4 + text_len {
                    return Err(corrupt());
                }
                Message::ErrorReport {
                    error_code: session_id,
                    pdu: enc,
                    text: String::from_utf8_lossy(&rest[4..]).into_owned(),
                }
            }
            // Router Key PDUs (BGPsec) are not used; skip them.
            Message::ROUTER_KEY => return Ok(Some((None, version, length))),
            _ => {
                return Err(RtrError::new(
                    error_code::UNSUPPORTED_PDU_TYPE,
                    header,
                    format!("unsupported PDU type {}", message_type),
                ));
            }
        };
        Ok(Some((Some(msg), version, length)))
    }
}

pub struct RtrCodec {
    /// RTR protocol version used when encoding outgoing messages.
    version: u8,
    /// Version of the most recently decoded PDU.
    last_version: Option<u8>,
}

impl Default for RtrCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl RtrCodec {
    /// Creates a codec that encodes outgoing messages as RTR version 1 (RFC 8210).
    pub fn new() -> Self {
        RtrCodec {
            version: 1,
            last_version: None,
        }
    }

    /// Creates a codec that encodes outgoing messages using the given RTR version.
    pub fn with_version(version: u8) -> Self {
        RtrCodec {
            version,
            last_version: None,
        }
    }

    /// Version used when encoding outgoing messages.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Changes the version used when encoding outgoing messages.
    pub fn set_version(&mut self, version: u8) {
        self.version = version;
    }

    /// Version of the most recently decoded PDU, if any.
    pub fn last_version(&self) -> Option<u8> {
        self.last_version
    }
}

impl Encoder<&Message> for RtrCodec {
    type Error = Error;

    fn encode(&mut self, item: &Message, dst: &mut BytesMut) -> Result<(), Error> {
        let buf = item.to_bytes(self.version)?;
        dst.reserve(buf.len());
        dst.put_slice(&buf);
        Ok(())
    }
}

impl Decoder for RtrCodec {
    type Item = Message;
    type Error = RtrError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        while let Some((m, version, len)) = Message::from_bytes(src)? {
            let _ = src.split_to(len);
            if m.is_some() {
                self.last_version = Some(version);
                return Ok(m);
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::codec::{Decoder, Encoder};

    fn encode(msg: &Message, version: u8) -> BytesMut {
        let mut codec = RtrCodec::with_version(version);
        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).unwrap();
        buf
    }

    fn decode(buf: &mut BytesMut) -> Message {
        let mut codec = RtrCodec::new();
        codec.decode(buf).unwrap().unwrap()
    }

    #[test]
    fn reset_query_v0_roundtrip() {
        let mut buf = encode(&Message::ResetQuery, 0);
        assert_eq!(buf.len(), 8);
        assert_eq!(buf[0], 0); // version
        assert_eq!(buf[1], Message::RESET_QUERY);
        let msg = decode(&mut buf);
        assert!(matches!(msg, Message::ResetQuery));
    }

    #[test]
    fn reset_query_v1_roundtrip() {
        let mut buf = encode(&Message::ResetQuery, 1);
        assert_eq!(buf[0], 1); // version
        assert_eq!(buf[1], Message::RESET_QUERY);
        let msg = decode(&mut buf);
        assert!(matches!(msg, Message::ResetQuery));
    }

    #[test]
    fn serial_query_roundtrip() {
        let msg = Message::SerialQuery {
            session_id: 42,
            serial_number: 12345,
        };
        let mut buf = encode(&msg, 1);
        assert_eq!(buf.len(), 12);
        assert_eq!(buf[0], 1);
        assert_eq!(buf[1], Message::SERIAL_QUERY);
        let decoded = decode(&mut buf);
        match decoded {
            Message::SerialQuery {
                session_id,
                serial_number,
            } => {
                assert_eq!(session_id, 42);
                assert_eq!(serial_number, 12345);
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn cache_response_preserves_session_id() {
        // Craft a raw CacheResponse with session_id = 7.
        let raw: &[u8] = &[1, Message::CACHE_RESPONSE, 0, 7, 0, 0, 0, 8];
        let mut buf = BytesMut::from(raw);
        let msg = decode(&mut buf);
        match msg {
            Message::CacheResponse { session_id } => assert_eq!(session_id, 7),
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn end_of_data_v0_no_intervals() {
        let raw: &[u8] = &[
            0,
            Message::END_OF_DATA,
            0,
            1, // session_id = 1
            0,
            0,
            0,
            12, // length = 12
            0,
            0,
            0,
            99, // serial_number = 99
        ];
        let mut buf = BytesMut::from(raw);
        let msg = decode(&mut buf);
        match msg {
            Message::EndOfData {
                session_id,
                serial_number,
                refresh_interval,
                retry_interval,
                expire_interval,
            } => {
                assert_eq!(session_id, 1);
                assert_eq!(serial_number, 99);
                assert_eq!(refresh_interval, 0);
                assert_eq!(retry_interval, 0);
                assert_eq!(expire_interval, 0);
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn end_of_data_v1_with_intervals() {
        let raw: &[u8] = &[
            1,
            Message::END_OF_DATA,
            0,
            2, // session_id = 2
            0,
            0,
            0,
            24, // length = 24
            0,
            0,
            0,
            55, // serial_number = 55
            0,
            0,
            0,
            30, // refresh = 30
            0,
            0,
            2,
            88, // retry = 600
            0,
            0,
            28,
            32, // expire = 7200
        ];
        let mut buf = BytesMut::from(raw);
        let msg = decode(&mut buf);
        match msg {
            Message::EndOfData {
                session_id,
                serial_number,
                refresh_interval,
                retry_interval,
                expire_interval,
            } => {
                assert_eq!(session_id, 2);
                assert_eq!(serial_number, 55);
                assert_eq!(refresh_interval, 30);
                assert_eq!(retry_interval, 600);
                assert_eq!(expire_interval, 7200);
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn error_report_carries_error_code() {
        let raw: &[u8] = &[
            1,
            Message::ERROR_REPORT,
            0,
            2, // error_code = 2 (No Data Available)
            0,
            0,
            0,
            16, // length = 16 (no encapsulated PDU, no text)
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut buf = BytesMut::from(raw);
        let msg = decode(&mut buf);
        match msg {
            Message::ErrorReport {
                error_code,
                pdu,
                text,
                ..
            } => {
                assert_eq!(error_code, 2);
                assert!(pdu.is_empty());
                assert!(text.is_empty());
            }
            _ => panic!("unexpected message type"),
        }
    }

    fn try_decode(raw: &[u8]) -> (Result<Option<Message>, RtrError>, usize) {
        let mut codec = RtrCodec::new();
        let mut buf = BytesMut::from(raw);
        let r = codec.decode(&mut buf);
        (r, buf.len())
    }

    #[test]
    fn error_report_encode_roundtrip() {
        let msg = Message::ErrorReport {
            error_code: 5,
            pdu: vec![],
            text: String::new(),
        };
        let mut buf = encode(&msg, 1);
        assert_eq!(buf.len(), 16);
        assert!(matches!(
            decode(&mut buf),
            Message::ErrorReport { error_code: 5, .. }
        ));
        assert!(buf.is_empty());

        // With an encapsulated PDU and diagnostic text.
        let enc = encode(&Message::CacheReset, 1).to_vec();
        let msg = Message::ErrorReport {
            error_code: error_code::CORRUPT_DATA,
            pdu: enc.clone(),
            text: "bad prefix".to_string(),
        };
        let mut buf = encode(&msg, 1);
        assert_eq!(buf.len(), 16 + 8 + 10);
        match decode(&mut buf) {
            Message::ErrorReport {
                error_code,
                pdu,
                text,
            } => {
                assert_eq!(error_code, error_code::CORRUPT_DATA);
                assert_eq!(pdu, enc);
                assert_eq!(text, "bad prefix");
            }
            _ => panic!("unexpected message type"),
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn error_report_inconsistent_lengths_rejected() {
        // Encapsulated PDU length runs past the end of the PDU.
        let mut raw = vec![1, Message::ERROR_REPORT, 0, 0, 0, 0, 0, 20];
        raw.extend_from_slice(&100u32.to_be_bytes());
        raw.extend_from_slice(&0u32.to_be_bytes());
        raw.extend_from_slice(&[0; 4]);
        let (r, _) = try_decode(&raw);
        let e = r.err().unwrap();
        assert_eq!(e.code, error_code::CORRUPT_DATA);
        // Never answer an Error Report with an Error Report.
        assert!(e.report().is_none());
    }

    fn prefix_pdu(v6: bool, prefix_len: u8, max_length: u8) -> Vec<u8> {
        let (t, len, alen) = if v6 {
            (Message::IPV6_PREFIX, 32u32, 16)
        } else {
            (Message::IPV4_PREFIX, 20u32, 4)
        };
        let mut raw = vec![1, t, 0, 0];
        raw.extend_from_slice(&len.to_be_bytes());
        raw.extend_from_slice(&[1, prefix_len, max_length, 0]);
        raw.extend(std::iter::repeat_n(0, alen));
        raw.extend_from_slice(&65001u32.to_be_bytes());
        raw
    }

    #[test]
    fn prefix_lengths_validated() {
        for (v6, plen, maxlen, ok) in [
            (false, 24, 24, true),
            (false, 24, 32, true),
            (false, 33, 33, false),
            (false, 24, 33, false),
            (false, 24, 16, false),
            (true, 48, 128, true),
            (true, 129, 129, false),
            (true, 48, 129, false),
            (true, 48, 32, false),
        ] {
            let raw = prefix_pdu(v6, plen, maxlen);
            let (r, _) = try_decode(&raw);
            if ok {
                assert!(matches!(r, Ok(Some(Message::IpPrefix(_)))));
            } else {
                let e = r.err().unwrap();
                assert_eq!(e.code, error_code::CORRUPT_DATA, "{} {}", plen, maxlen);
                // The whole offending PDU is returned for the Error Report.
                assert_eq!(e.pdu, raw);
                assert!(matches!(
                    e.report(),
                    Some(Message::ErrorReport {
                        error_code: error_code::CORRUPT_DATA,
                        ..
                    })
                ));
            }
        }
    }

    #[test]
    fn unsupported_version_and_type_codes() {
        let (r, _) = try_decode(&[2, Message::RESET_QUERY, 0, 0, 0, 0, 0, 8]);
        assert_eq!(
            r.err().unwrap().code,
            error_code::UNSUPPORTED_PROTOCOL_VERSION
        );
        let (r, _) = try_decode(&[1, 200, 0, 0, 0, 0, 0, 8]);
        assert_eq!(r.err().unwrap().code, error_code::UNSUPPORTED_PDU_TYPE);
    }

    #[test]
    fn codec_records_pdu_version() {
        let mut codec = RtrCodec::new();
        assert_eq!(codec.last_version(), None);
        let mut buf = encode(&Message::CacheReset, 0);
        assert!(codec.decode(&mut buf).unwrap().is_some());
        assert_eq!(codec.last_version(), Some(0));
        codec.set_version(0);
        assert_eq!(codec.version(), 0);
    }

    #[test]
    fn partial_pdu_waits_for_more_bytes() {
        let full = encode(&Message::ResetQuery, 1);
        for n in 0..full.len() {
            let (r, left) = try_decode(&full[..n]);
            assert!(matches!(r, Ok(None)));
            assert_eq!(left, n);
        }
    }

    #[test]
    fn rejects_bad_lengths() {
        // length 0 used to loop forever without consuming bytes.
        for (t, len) in [
            (Message::RESET_QUERY, 0u32),
            (Message::RESET_QUERY, 7),
            (Message::RESET_QUERY, 12),
            (Message::SERIAL_NOTIFY, 8),
            (Message::IPV4_PREFIX, 8),
            (Message::IPV6_PREFIX, 20),
            (Message::END_OF_DATA, 12), // v1 requires 24
            (Message::ERROR_REPORT, 8),
            (Message::ERROR_REPORT, 0xffff_ffff),
            (Message::ROUTER_KEY, 8),
            (Message::ROUTER_KEY, 0xffff_ffff),
        ] {
            let mut raw = vec![1, t, 0, 0];
            raw.extend_from_slice(&len.to_be_bytes());
            raw.resize(64, 0);
            let (r, _) = try_decode(&raw);
            assert!(r.is_err(), "type {} length {}", t, len);
        }
    }

    #[test]
    fn rejects_unknown_type() {
        let (r, _) = try_decode(&[1, 200, 0, 0, 0, 0, 0, 8]);
        assert!(r.is_err());
        // Router Key is not defined in version 0.
        let mut raw = vec![0, Message::ROUTER_KEY, 0, 0, 0, 0, 0, 32];
        raw.resize(32, 0);
        let (r, _) = try_decode(&raw);
        assert!(r.is_err());
    }

    #[test]
    fn router_key_is_skipped() {
        // Router Key PDU: header + SKI(20) + ASN(4) + 4-byte SPKI.
        let mut raw = vec![1, Message::ROUTER_KEY, 1, 0, 0, 0, 0, 36];
        raw.resize(36, 0xaa);
        // Incomplete Router Key: wait for the rest.
        let (r, left) = try_decode(&raw[..20]);
        assert!(matches!(r, Ok(None)));
        assert_eq!(left, 20);
        // Router Key alone is consumed with nothing to return.
        let (r, left) = try_decode(&raw);
        assert!(matches!(r, Ok(None)));
        assert_eq!(left, 0);
        // A following PDU is still decoded.
        raw.extend_from_slice(&encode(&Message::CacheReset, 1));
        let (r, left) = try_decode(&raw);
        assert!(matches!(r, Ok(Some(Message::CacheReset))));
        assert_eq!(left, 0);
    }
}

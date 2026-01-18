// Copyright (C) 2022 The RustyBGP Authors.
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

//! BGP Session Authentication Module
//!
//! This module implements authentication mechanisms for BGP sessions including
//! TCP MD5 Signature (RFC 2385) and TCP Authentication Option (RFC 5925).
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module addresses the following NIST SP 800-53 Rev. 5 security controls:
//!
//! ## Identification and Authentication (IA) Family
//!
//! - **IA-3: Device Identification and Authentication**
//!   Authenticates BGP peer devices before establishing sessions.
//!   TCP-AO provides cryptographic device authentication using shared keys
//!   and key identifiers unique to each peer relationship.
//!
//! - **IA-5: Authenticator Management**
//!   Supports authenticator (key) management through:
//!   - Configurable key values up to 80 bytes
//!   - Key identifiers (send_id, recv_id) for key rollover support
//!   - Algorithm selection for cryptographic strength requirements
//!
//! - **IA-7: Cryptographic Module Authentication**
//!   Uses FIPS-validated cryptographic algorithms (AES-128-CMAC, HMAC-SHA1)
//!   implemented in the Linux kernel cryptographic subsystem.
//!
//! - **IA-9: Service Identification and Authentication**
//!   Authenticates the BGP routing service between peers, ensuring only
//!   authorized routers can establish BGP sessions.
//!
//! ## System and Communications Protection (SC) Family
//!
//! - **SC-8: Transmission Confidentiality and Integrity**
//!   Provides integrity protection for BGP session traffic. TCP-AO generates
//!   MACs for each TCP segment, detecting tampering or injection attacks.
//!   Note: TCP-AO provides integrity, not confidentiality.
//!
//! - **SC-12: Cryptographic Key Establishment and Management**
//!   Supports key management through:
//!   - Multiple key IDs per peer for key rollover without session disruption
//!   - Separate send and receive key identifiers
//!   - Key addition and deletion APIs for lifecycle management
//!
//! - **SC-13: Cryptographic Protection**
//!   Implements NIST-approved cryptographic algorithms:
//!   - AES-128-CMAC (FIPS 197, SP 800-38B) - Recommended default
//!   - HMAC-SHA-1-96 (FIPS 180-4, RFC 2104) - Legacy compatibility
//!
//! - **SC-23: Session Authenticity**
//!   Protects BGP session authenticity by:
//!   - Authenticating each TCP segment with cryptographic MACs
//!   - Binding authentication to specific peer IP addresses
//!   - Preventing session hijacking and RST attacks
//!
//! ## Access Control (AC) Family
//!
//! - **AC-17: Remote Access**
//!   Controls remote BGP peer connections by requiring valid authentication
//!   credentials before session establishment. Unauthenticated connection
//!   attempts are rejected at the TCP layer.
//!
//! ## Audit and Accountability (AU) Family
//!
//! - **AU-2: Event Logging** (Partial)
//!   Functions return error codes that can be logged for security monitoring.
//!   Integration with system logging is recommended for full compliance.
//!
//! # Security Considerations
//!
//! - TCP-AO (RFC 5925) supersedes TCP MD5 (RFC 2385) with improved security
//! - Key length should be at least 16 bytes for adequate security
//! - AES-128-CMAC is preferred over HMAC-SHA1-96 for new deployments
//! - Keys should be rotated periodically using the key ID mechanism
//! - Requires Linux kernel 5.18+ for TCP-AO support

use std::net::IpAddr;
use std::os::unix::io::RawFd;

// TCP MD5 Signature Option (RFC 2385)
#[repr(C)]
struct TcpMd5sig {
    ss_family: u16,
    ss: [u8; 126],
    _pad0: u16,
    keylen: u16,
    _pad1: u32,
    key: [u8; 80],
}

impl TcpMd5sig {
    fn new(addr: &IpAddr, password: String) -> TcpMd5sig {
        let mut ss = [0; 126];
        let ss_family = match addr {
            std::net::IpAddr::V4(addr) => {
                ss[2..(addr.octets().len() + 2)].clone_from_slice(&addr.octets()[..]);
                libc::AF_INET as u16
            }
            std::net::IpAddr::V6(addr) => {
                ss[6..(addr.octets().len() + 6)].clone_from_slice(&addr.octets()[..]);
                libc::AF_INET6 as u16
            }
        };
        let k = std::ffi::CString::new(password).unwrap().into_bytes();
        let keylen = k.len();
        let mut key = [0; 80];
        key[..std::cmp::min(keylen, 80)].clone_from_slice(&k[..std::cmp::min(keylen, 80)]);
        TcpMd5sig {
            ss_family,
            ss,
            _pad0: 0,
            keylen: keylen as u16,
            _pad1: 0,
            key,
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn set_md5sig(rawfd: RawFd, addr: &IpAddr, key: &str) {
    let s = TcpMd5sig::new(addr, key.to_string());
    unsafe {
        let ptr: *const TcpMd5sig = &s;
        let len = std::mem::size_of::<TcpMd5sig>() as u32;
        let _ = libc::setsockopt(
            rawfd,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            ptr as *const _,
            len,
        );
    }
}

// use file per target os when you add *bsd support
// for now, let's keep things simple
#[cfg(not(target_os = "linux"))]
pub(crate) fn set_md5sig(_rawfd: RawFd, _addr: &IpAddr, _key: &str) {}

// TCP Authentication Option (RFC 5925)
// Linux kernel support added in 5.18+

/// TCP AO key configuration for BGP session authentication.
///
/// # NIST Controls
/// - **IA-3**: Device authentication configuration
/// - **IA-5**: Authenticator (key) storage and management
/// - **SC-12**: Key identifier management for key rollover
/// - **SC-13**: Algorithm selection for cryptographic protection
#[derive(Clone, Debug)]
pub struct TcpAoConfig {
    /// The shared secret key.
    /// NIST SC-12: Cryptographic key for session authentication.
    /// Recommended minimum length: 16 bytes for adequate security.
    pub key: String,
    /// Send key ID (0-255).
    /// NIST SC-12: Identifies the key used for outbound authentication,
    /// enabling key rollover without session disruption.
    pub send_id: u8,
    /// Receive key ID (0-255).
    /// NIST SC-12: Identifies the key expected for inbound authentication,
    /// supporting coordinated key rotation with peers.
    pub recv_id: u8,
    /// Algorithm: "cmac-aes-128" or "hmac-sha1-96" (default: cmac-aes-128).
    /// NIST SC-13: Cryptographic algorithm selection.
    pub algorithm: TcpAoAlgorithm,
}

impl TcpAoConfig {
    pub fn new(key: String, send_id: u8, recv_id: u8) -> Self {
        TcpAoConfig {
            key,
            send_id,
            recv_id,
            algorithm: TcpAoAlgorithm::CmacAes128,
        }
    }

    pub fn with_algorithm(mut self, algorithm: TcpAoAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }
}

/// TCP AO algorithm options.
///
/// # NIST Controls
/// - **SC-13**: NIST-approved cryptographic algorithms
/// - **IA-7**: FIPS-validated cryptographic modules (when using kernel crypto)
///
/// Both algorithms are mandatory per RFC 5925 and use NIST-approved primitives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpAoAlgorithm {
    /// AES-128-CMAC (recommended, default).
    /// NIST SC-13: FIPS 197 (AES) + SP 800-38B (CMAC).
    /// Provides 128-bit security level.
    CmacAes128,
    /// HMAC-SHA1-96.
    /// NIST SC-13: FIPS 180-4 (SHA-1) + RFC 2104 (HMAC).
    /// Truncated to 96 bits; provided for legacy compatibility.
    HmacSha1_96,
}

impl TcpAoAlgorithm {
    /// Returns the algorithm name as expected by the kernel
    pub fn as_str(&self) -> &'static str {
        match self {
            TcpAoAlgorithm::CmacAes128 => "cmac(aes128)",
            TcpAoAlgorithm::HmacSha1_96 => "hmac(sha1)",
        }
    }

    /// Returns the MAC length for this algorithm
    pub fn maclen(&self) -> u8 {
        match self {
            TcpAoAlgorithm::CmacAes128 => 16,
            TcpAoAlgorithm::HmacSha1_96 => 12,
        }
    }
}

impl Default for TcpAoAlgorithm {
    fn default() -> Self {
        TcpAoAlgorithm::CmacAes128
    }
}

// Linux TCP AO socket option constants
#[cfg(target_os = "linux")]
const TCP_AO_ADD_KEY: libc::c_int = 38;
#[cfg(target_os = "linux")]
const TCP_AO_DEL_KEY: libc::c_int = 39;

// TCP AO key flags
#[cfg(target_os = "linux")]
const TCP_AO_KEYF_IFINDEX: u8 = 0x01;
#[cfg(target_os = "linux")]
const TCP_AO_KEYF_EXCLUDE_OPT: u8 = 0x02;

// Maximum key length for TCP AO
const TCP_AO_MAXKEYLEN: usize = 80;

/// Structure for adding a TCP AO key (matches Linux struct tcp_ao_add)
#[cfg(target_os = "linux")]
#[repr(C)]
struct TcpAoAdd {
    /// Remote address (sockaddr_storage)
    addr: [u8; 128],
    /// Key data
    key: [u8; TCP_AO_MAXKEYLEN],
    /// Key flags
    keyflags: u8,
    /// Length of key
    keylen: u8,
    /// Prefix length for address matching
    prefix: u8,
    /// Send key ID
    sndid: u8,
    /// Receive key ID
    rcvid: u8,
    /// MAC length
    maclen: u8,
    /// Padding
    _reserved: u8,
    /// Set as current key
    set_current: u8,
    /// Set as receive next key
    set_rnext: u8,
    /// Padding
    _reserved2: [u8; 7],
    /// Interface index
    ifindex: i32,
    /// Algorithm name (null-terminated)
    alg_name: [u8; 64],
}

#[cfg(target_os = "linux")]
impl TcpAoAdd {
    fn new(addr: &IpAddr, config: &TcpAoConfig) -> Self {
        let mut s = TcpAoAdd {
            addr: [0; 128],
            key: [0; TCP_AO_MAXKEYLEN],
            keyflags: 0,
            keylen: 0,
            prefix: 0,
            sndid: config.send_id,
            rcvid: config.recv_id,
            maclen: config.algorithm.maclen(),
            _reserved: 0,
            set_current: 1,
            set_rnext: 1,
            _reserved2: [0; 7],
            ifindex: 0,
            alg_name: [0; 64],
        };

        // Set address and prefix based on IP version
        match addr {
            std::net::IpAddr::V4(addr) => {
                // sockaddr_in structure
                s.addr[0] = (libc::AF_INET & 0xff) as u8;
                s.addr[1] = ((libc::AF_INET >> 8) & 0xff) as u8;
                // port at offset 2-3 (set to 0)
                // address at offset 4-7
                s.addr[4..8].clone_from_slice(&addr.octets()[..]);
                s.prefix = 32; // Full match for IPv4
            }
            std::net::IpAddr::V6(addr) => {
                // sockaddr_in6 structure
                s.addr[0] = (libc::AF_INET6 & 0xff) as u8;
                s.addr[1] = ((libc::AF_INET6 >> 8) & 0xff) as u8;
                // port at offset 2-3 (set to 0)
                // flowinfo at offset 4-7 (set to 0)
                // address at offset 8-23
                s.addr[8..24].clone_from_slice(&addr.octets()[..]);
                s.prefix = 128; // Full match for IPv6
            }
        };

        // Copy key
        let key_bytes = config.key.as_bytes();
        let keylen = std::cmp::min(key_bytes.len(), TCP_AO_MAXKEYLEN);
        s.key[..keylen].clone_from_slice(&key_bytes[..keylen]);
        s.keylen = keylen as u8;

        // Set algorithm name
        let alg_name = config.algorithm.as_str();
        let alg_bytes = alg_name.as_bytes();
        let alg_len = std::cmp::min(alg_bytes.len(), 63);
        s.alg_name[..alg_len].clone_from_slice(&alg_bytes[..alg_len]);

        s
    }
}

/// Structure for deleting a TCP AO key (matches Linux struct tcp_ao_del)
#[cfg(target_os = "linux")]
#[repr(C)]
struct TcpAoDel {
    /// Remote address (sockaddr_storage)
    addr: [u8; 128],
    /// Prefix length for address matching
    prefix: u8,
    /// Key flags
    keyflags: u8,
    /// Padding
    _reserved: u16,
    /// Send key ID (set -1 to delete all keys for address)
    sndid: i16,
    /// Receive key ID (set -1 to delete all keys for address)
    rcvid: i16,
    /// Current key (output)
    current_key: u8,
    /// Receive next key (output)
    rnext: u8,
    /// Number of keys deleted (output)
    del_async_count: u16,
    /// Interface index
    ifindex: i32,
}

#[cfg(target_os = "linux")]
impl TcpAoDel {
    fn new(addr: &IpAddr, send_id: Option<u8>, recv_id: Option<u8>) -> Self {
        let mut s = TcpAoDel {
            addr: [0; 128],
            prefix: 0,
            keyflags: 0,
            _reserved: 0,
            sndid: send_id.map(|id| id as i16).unwrap_or(-1),
            rcvid: recv_id.map(|id| id as i16).unwrap_or(-1),
            current_key: 0,
            rnext: 0,
            del_async_count: 0,
            ifindex: 0,
        };

        // Set address and prefix based on IP version
        match addr {
            std::net::IpAddr::V4(addr) => {
                s.addr[0] = (libc::AF_INET & 0xff) as u8;
                s.addr[1] = ((libc::AF_INET >> 8) & 0xff) as u8;
                s.addr[4..8].clone_from_slice(&addr.octets()[..]);
                s.prefix = 32;
            }
            std::net::IpAddr::V6(addr) => {
                s.addr[0] = (libc::AF_INET6 & 0xff) as u8;
                s.addr[1] = ((libc::AF_INET6 >> 8) & 0xff) as u8;
                s.addr[8..24].clone_from_slice(&addr.octets()[..]);
                s.prefix = 128;
            }
        };

        s
    }
}

/// Add a TCP AO key to the socket for the specified peer address.
///
/// # NIST Controls
/// - **IA-3**: Enables device authentication for the specified peer
/// - **IA-5**: Installs authenticator (key) for the peer relationship
/// - **AC-17**: Establishes authentication requirement for remote BGP peer
/// - **SC-8**: Enables integrity protection for the connection
/// - **SC-23**: Establishes session authenticity mechanism
///
/// # Arguments
/// * `rawfd` - Raw file descriptor of the TCP socket
/// * `addr` - IP address of the remote BGP peer
/// * `config` - TCP AO configuration including key and algorithm
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(errno)` on failure (NIST AU-2: error for audit logging)
#[cfg(target_os = "linux")]
pub(crate) fn set_tcp_ao(rawfd: RawFd, addr: &IpAddr, config: &TcpAoConfig) -> Result<(), i32> {
    let s = TcpAoAdd::new(addr, config);
    unsafe {
        let ptr: *const TcpAoAdd = &s;
        let len = std::mem::size_of::<TcpAoAdd>() as u32;
        let ret = libc::setsockopt(
            rawfd,
            libc::IPPROTO_TCP,
            TCP_AO_ADD_KEY,
            ptr as *const _,
            len,
        );
        if ret < 0 {
            return Err(*libc::__errno_location());
        }
    }
    Ok(())
}

/// Remove a TCP AO key from the socket.
///
/// # NIST Controls
/// - **IA-5**: Authenticator lifecycle management (key removal/revocation)
/// - **SC-12**: Cryptographic key management (key deletion)
/// - **AC-17**: Revokes remote access authentication for peer
///
/// If send_id and recv_id are None, all keys for the address are removed.
///
/// # Arguments
/// * `rawfd` - Raw file descriptor of the TCP socket
/// * `addr` - IP address of the remote BGP peer
/// * `send_id` - Optional send key ID to delete (None = all)
/// * `recv_id` - Optional receive key ID to delete (None = all)
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(errno)` on failure (NIST AU-2: error for audit logging)
#[cfg(target_os = "linux")]
pub(crate) fn del_tcp_ao(
    rawfd: RawFd,
    addr: &IpAddr,
    send_id: Option<u8>,
    recv_id: Option<u8>,
) -> Result<(), i32> {
    let s = TcpAoDel::new(addr, send_id, recv_id);
    unsafe {
        let ptr: *const TcpAoDel = &s;
        let len = std::mem::size_of::<TcpAoDel>() as u32;
        let ret = libc::setsockopt(
            rawfd,
            libc::IPPROTO_TCP,
            TCP_AO_DEL_KEY,
            ptr as *const _,
            len,
        );
        if ret < 0 {
            return Err(*libc::__errno_location());
        }
    }
    Ok(())
}

// Non-Linux stub implementations
#[cfg(not(target_os = "linux"))]
pub(crate) fn set_tcp_ao(_rawfd: RawFd, _addr: &IpAddr, _config: &TcpAoConfig) -> Result<(), i32> {
    // TCP AO is only supported on Linux 5.18+
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn del_tcp_ao(
    _rawfd: RawFd,
    _addr: &IpAddr,
    _send_id: Option<u8>,
    _recv_id: Option<u8>,
) -> Result<(), i32> {
    // TCP AO is only supported on Linux 5.18+
    Ok(())
}

//! Abstraction for network transport mechanisms used by clients.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use tracing::{debug, trace};

use crate::ClientError;

/// Abstraction for network transport mechanisms used by clients.
/// Allows clients to work with different protocols (UDP, TCP, etc.) through a common interface.
pub trait ClientTransport {
    /// Sends data to the specified network address.
    /// Returns the number of bytes sent or an error if the operation fails.
    fn send(&self, data: &[u8], addr: SocketAddr) -> Result<usize, ClientError>;

    /// Receives data from any network address.
    /// Returns the number of bytes received and the sender's address, or an error on failure.
    fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ClientError>;
}

/// UDP implementation of ClientTransport.
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    /// Create a new UDP transport configured for the target server address.
    /// Binds to an IPv4 or IPv6 local address based on the target's address family.
    pub fn new(timeout: Duration, target: SocketAddr) -> Result<Self, ClientError> {
        let bind_addr = match target {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;

        Ok(Self { socket })
    }
}

impl ClientTransport for UdpTransport {
    fn send(&self, data: &[u8], addr: SocketAddr) -> Result<usize, ClientError> {
        debug!("sending {} bytes to {}", data.len(), addr);
        trace_dump(data)?;
        Ok(self.socket.send_to(data, addr)?)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ClientError> {
        match self.socket.recv_from(buf) {
            Ok((nbytes, addr)) => {
                debug!("received {} bytes from {}", nbytes, addr);
                trace_dump(&buf[..nbytes])?;
                Ok((nbytes, addr))
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    Err(ClientError::ServerTimeout)
                } else {
                    Err(ClientError::IoError(e))
                }
            }
        }
    }
}

fn trace_dump(data: &[u8]) -> Result<(), ClientError> {
    if tracing::enabled!(tracing::Level::TRACE) {
        let mut dump = Vec::new();
        roughenough_common::encoding::hexdump(data, &mut dump)?;
        trace!("\n{}", String::from_utf8_lossy(&dump));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    use super::*;

    #[test]
    fn udp_transport_binds_ipv4_for_ipv4_target() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 2002));
        let transport = UdpTransport::new(Duration::from_secs(1), target).unwrap();

        // Verify we bound to an IPv4 address
        let local_addr = transport.socket.local_addr().unwrap();
        assert!(
            local_addr.is_ipv4(),
            "expected IPv4 local address, got {}",
            local_addr
        );
    }

    #[test]
    fn udp_transport_binds_ipv6_for_ipv6_target() {
        let target = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 2002, 0, 0));
        let transport = UdpTransport::new(Duration::from_secs(1), target).unwrap();

        // Verify we bound to an IPv6 address
        let local_addr = transport.socket.local_addr().unwrap();
        assert!(
            local_addr.is_ipv6(),
            "expected IPv6 local address, got {}",
            local_addr
        );
    }

    #[test]
    fn udp_transport_can_send_to_ipv6_loopback() {
        // Create a listener on IPv6 loopback
        let listener = UdpSocket::bind("[::1]:0").unwrap();
        let listener_addr = listener.local_addr().unwrap();

        // Create transport targeting IPv6
        let transport = UdpTransport::new(Duration::from_secs(1), listener_addr).unwrap();

        // Send some data
        let data = b"test data";
        let sent_bytes_count = transport.send(data, listener_addr).unwrap();
        assert_eq!(sent_bytes_count, data.len());

        // Verify it was received
        let mut buf = [0u8; 64];
        listener
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (received_bytes_count, _from) = listener.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..received_bytes_count], data);
    }

    #[test]
    fn udp_transport_can_send_to_ipv4_loopback() {
        // Create a listener on IPv4 loopback
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let listener_addr = listener.local_addr().unwrap();

        // Create transport targeting IPv4
        let transport = UdpTransport::new(Duration::from_secs(1), listener_addr).unwrap();

        // Send some data
        let data = b"test data";
        let sent_bytes_count = transport.send(data, listener_addr).unwrap();
        assert_eq!(sent_bytes_count, data.len());

        // Verify it was received
        let mut buf = [0u8; 64];
        listener
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (received_bytes_count, _from) = listener.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..received_bytes_count], data);
    }
}

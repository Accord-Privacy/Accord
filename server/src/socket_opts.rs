//! TCP options of the relay's client connections (SPEC-03 amendment A2,
//! §14.2 and §6.12.3).
//!
//! Over one TCP connection, bytes already handed to the operating system
//! cannot be recalled, and the screen queue's 2 s age check (§6.12.3) bounds
//! only what is still in the relay's own queue. So that the kernel send
//! buffer does not hold seconds of video behind it, the relay sets
//! `TCP_NOTSENT_LOWAT` to [`RELAY_NOTSENT_LOWAT`] (32,768 bytes) on every
//! WebSocket connection's TCP socket where the platform supports it (Linux
//! and macOS). The socket then reports itself writable, and accepts writes,
//! only while its unsent data is below that mark, so unsent data in the
//! relay's kernel buffer stays near it; data in flight is bounded by the
//! receiver's window.
//!
//! The option is set when a connection is accepted ([`NotsentLowatAcceptor`]),
//! before the HTTP request is read, so every connection that becomes a
//! WebSocket has it. Plain HTTP requests on the same listener get it too,
//! which costs them nothing: the mark limits unsent data only, not data in
//! flight. The relay's two listeners are built here ([`plain_server`] and
//! [`tls_server`]), so `main.rs` and the tests use the same construction.
//! Where the platform has no such option the relay logs that once at
//! startup, when its listener is built ([`log_support_at_startup`]); where
//! setting it fails on a connection, the first failure is logged once.

use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use axum_server::Server;
use std::future::{ready, Ready};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;
use tokio::net::TcpStream;

/// `RELAY_NOTSENT_LOWAT` (A2): the most unsent data, in bytes, the relay lets
/// its kernel buffer hold on a client connection.
pub const RELAY_NOTSENT_LOWAT: u32 = 32_768;

#[cfg(any(target_os = "linux", target_os = "android"))]
const TCP_NOTSENT_LOWAT: libc::c_int = libc::TCP_NOTSENT_LOWAT;
/// `TCP_NOTSENT_LOWAT` in Apple's `<netinet/tcp.h>` (the `libc` crate does
/// not export it for Apple targets).
#[cfg(any(target_os = "macos", target_os = "ios"))]
const TCP_NOTSENT_LOWAT: libc::c_int = 0x201;

/// Whether this platform has `TCP_NOTSENT_LOWAT` (Linux and macOS).
pub const fn notsent_lowat_supported() -> bool {
    cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))
}

/// Set `TCP_NOTSENT_LOWAT` on `socket` to `bytes`.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
pub fn set_notsent_lowat<S: std::os::fd::AsRawFd>(socket: &S, bytes: u32) -> io::Result<()> {
    let value = libc::c_int::try_from(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "TCP_NOTSENT_LOWAT value"))?;
    // SAFETY: `socket` owns an open file descriptor for the duration of the
    // call, and `value` is a live `c_int` whose exact size is passed as the
    // option length; setsockopt only reads it.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_NOTSENT_LOWAT,
            (&value as *const libc::c_int).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Without `TCP_NOTSENT_LOWAT` on this platform: always `Unsupported`.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
pub fn set_notsent_lowat<S>(_socket: &S, _bytes: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP_NOTSENT_LOWAT is not available on this platform",
    ))
}

/// Read `TCP_NOTSENT_LOWAT` back from `socket` (tests and diagnostics).
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
pub fn notsent_lowat<S: std::os::fd::AsRawFd>(socket: &S) -> io::Result<u32> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `value` and `len` are live locals; getsockopt writes at most
    // `len` bytes into `value` and updates `len`.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_NOTSENT_LOWAT,
            (&mut value as *mut libc::c_int).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // The kernel keeps the mark as an unsigned 32-bit value.
    Ok(value as u32)
}

/// The first failure to set the option on a connection has been logged.
static FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);

/// Apply [`RELAY_NOTSENT_LOWAT`] to an accepted connection. A failure never
/// refuses the connection; the first one is logged.
pub fn apply_to(stream: &TcpStream) {
    if !notsent_lowat_supported() {
        return; // logged once at startup
    }
    if let Err(e) = set_notsent_lowat(stream, RELAY_NOTSENT_LOWAT) {
        if !FAILURE_LOGGED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "could not set TCP_NOTSENT_LOWAT to {} bytes on a client connection ({}); \
                 unsent data in the kernel's send buffer is then not bounded by the relay \
                 (logged once)",
                RELAY_NOTSENT_LOWAT,
                e
            );
        }
    }
}

/// The support has been logged.
static SUPPORT_LOGGED: Once = Once::new();

/// Log once, at startup, whether client connections get the option. The
/// listener builders call it; later calls log nothing.
pub fn log_support_at_startup() {
    SUPPORT_LOGGED.call_once(log_support);
}

fn log_support() {
    if notsent_lowat_supported() {
        tracing::info!(
            "TCP_NOTSENT_LOWAT: {} bytes on every client connection",
            RELAY_NOTSENT_LOWAT
        );
    } else {
        tracing::warn!(
            "TCP_NOTSENT_LOWAT is not supported on this platform: unsent data in the kernel's \
             send buffer of a client connection is bounded only by the buffer size, so screen \
             video to a slow viewer can arrive later than on Linux or macOS"
        );
    }
}

/// An `axum_server` acceptor that sets `TCP_NOTSENT_LOWAT` on every accepted
/// TCP connection, before TLS (if any) and before the HTTP request is read.
#[derive(Clone, Copy, Debug, Default)]
pub struct NotsentLowatAcceptor;

impl<S> Accept<TcpStream, S> for NotsentLowatAcceptor {
    type Stream = TcpStream;
    type Service = S;
    type Future = Ready<io::Result<(TcpStream, S)>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        apply_to(&stream);
        ready(Ok((stream, service)))
    }
}

/// The relay's plain HTTP and WebSocket listener on `listener`: every
/// accepted connection gets `TCP_NOTSENT_LOWAT` through
/// [`NotsentLowatAcceptor`] (SPEC-03 A2, §6.12.3). Logs the support once.
/// `listener` must be in non-blocking mode (as `tokio`'s `into_std` leaves it).
pub fn plain_server(listener: std::net::TcpListener) -> Server<NotsentLowatAcceptor> {
    log_support_at_startup();
    axum_server::from_tcp(listener).acceptor(NotsentLowatAcceptor)
}

/// The relay's TLS listener on `addr`: every accepted connection gets
/// `TCP_NOTSENT_LOWAT` before the TLS handshake (SPEC-03 A2, §6.12.3).
/// Logs the support once.
pub fn tls_server(
    addr: SocketAddr,
    config: RustlsConfig,
) -> Server<RustlsAcceptor<NotsentLowatAcceptor>> {
    log_support_at_startup();
    axum_server::bind_rustls(addr, config).map(|tls| tls.acceptor(NotsentLowatAcceptor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    #[test]
    fn the_mark_is_32_kib() {
        assert_eq!(RELAY_NOTSENT_LOWAT, 32_768);
    }

    #[test]
    fn linux_and_macos_support_it_windows_does_not() {
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(notsent_lowat_supported());
        }
        if cfg!(target_os = "windows") {
            assert!(!notsent_lowat_supported());
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn the_acceptor_sets_the_mark_on_every_accepted_connection() {
        let (_client, accepted) = pair().await;
        let before = notsent_lowat(&accepted).unwrap();
        assert_ne!(
            before, RELAY_NOTSENT_LOWAT,
            "the kernel's default is not the relay's mark"
        );
        let (stream, ()) = NotsentLowatAcceptor.accept(accepted, ()).await.unwrap();
        assert_eq!(notsent_lowat(&stream).unwrap(), RELAY_NOTSENT_LOWAT);
        // A second connection gets it too.
        let (_c2, a2) = pair().await;
        let (s2, ()) = NotsentLowatAcceptor.accept(a2, ()).await.unwrap();
        assert_eq!(notsent_lowat(&s2).unwrap(), RELAY_NOTSENT_LOWAT);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn set_and_read_back() {
        let (client, _accepted) = pair().await;
        set_notsent_lowat(&client, 16_384).unwrap();
        assert_eq!(notsent_lowat(&client).unwrap(), 16_384);
        set_notsent_lowat(&client, RELAY_NOTSENT_LOWAT).unwrap();
        assert_eq!(notsent_lowat(&client).unwrap(), RELAY_NOTSENT_LOWAT);
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    #[tokio::test]
    async fn unsupported_platforms_report_unsupported_and_accept_anyway() {
        let (_client, accepted) = pair().await;
        let err = set_notsent_lowat(&accepted, RELAY_NOTSENT_LOWAT).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(NotsentLowatAcceptor.accept(accepted, ()).await.is_ok());
    }
}

//! SPEC-03 amendment A2 (§14.2, §6.12.3): the relay sets `TCP_NOTSENT_LOWAT`
//! to `RELAY_NOTSENT_LOWAT` (32,768 bytes) on every WebSocket connection's
//! TCP socket where the platform supports it, and logs once at startup where
//! it does not.
//!
//! The option itself is tested in `src/socket_opts.rs`. These tests build
//! the relay's two listeners with the functions `main.rs` serves the relay
//! on (`socket_opts::plain_server` and `socket_opts::tls_server`), wrap
//! whatever acceptor those functions chose, and check that the socket each
//! WebSocket arrives on carries the mark once that acceptor has run (for
//! TLS, after the handshake).

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod live {
    use accord_server::socket_opts::{
        notsent_lowat, plain_server, tls_server, RELAY_NOTSENT_LOWAT,
    };
    use axum::{extract::ws::WebSocketUpgrade, routing::get, Router};
    use axum_server::accept::Accept;
    use axum_server::tls_rustls::RustlsConfig;
    use futures_util::{SinkExt, StreamExt};
    use std::future::Future;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::net::TcpStream;
    use tokio_tungstenite::tungstenite::Message;

    /// Wraps the acceptor a listener function chose and records the mark of
    /// each socket it hands on.
    #[derive(Clone)]
    struct Recording<A> {
        inner: A,
        seen: Arc<Mutex<Vec<u32>>>,
    }

    impl<A, S> Accept<TcpStream, S> for Recording<A>
    where
        A: Accept<TcpStream, S>,
        A::Stream: AsRawFd + Send + 'static,
        A::Service: Send + 'static,
        A::Future: Send + 'static,
    {
        type Stream = A::Stream;
        type Service = A::Service;
        type Future = Pin<Box<dyn Future<Output = io::Result<(A::Stream, A::Service)>> + Send>>;

        fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
            let seen = self.seen.clone();
            let inner = self.inner.accept(stream, service);
            Box::pin(async move {
                let (stream, service) = inner.await?;
                seen.lock().unwrap().push(notsent_lowat(&stream)?);
                Ok((stream, service))
            })
        }
    }

    /// An echo WebSocket at `/ws`.
    fn echo_app() -> Router {
        Router::new().route(
            "/ws",
            get(|ws: WebSocketUpgrade| async move {
                ws.on_upgrade(|mut socket| async move {
                    while let Some(Ok(msg)) = socket.recv().await {
                        if socket.send(msg).await.is_err() {
                            break;
                        }
                    }
                })
            }),
        )
    }

    /// One WebSocket round trip over `stream`.
    async fn ping<S: AsyncRead + AsyncWrite + Unpin>(url: &str, stream: S) {
        let (mut ws, _) = tokio_tungstenite::client_async(url, stream)
            .await
            .expect("websocket");
        ws.send(Message::Text("ping".into())).await.unwrap();
        let echo = ws.next().await.expect("echo").expect("echo frame");
        assert_eq!(echo.into_text().unwrap(), "ping");
    }

    #[tokio::test]
    async fn a2_the_plain_listener_gives_every_websocket_the_mark() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handle = axum_server::Handle::new();
        let recording = seen.clone();
        let server = plain_server(listener.into_std().unwrap())
            .map(move |inner| Recording {
                inner,
                seen: recording,
            })
            .handle(handle.clone())
            .serve(echo_app().into_make_service());
        let task = tokio::spawn(server);

        for _ in 0..2 {
            let tcp = TcpStream::connect(addr).await.unwrap();
            ping(&format!("ws://{addr}/ws"), tcp).await;
        }
        assert_eq!(*seen.lock().unwrap(), vec![RELAY_NOTSENT_LOWAT; 2]);

        handle.shutdown();
        let _ = task.await;
    }

    #[tokio::test]
    async fn a2_the_tls_listener_gives_every_websocket_the_mark() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let config =
            RustlsConfig::from_pem(cert.pem().into_bytes(), key.serialize_pem().into_bytes())
                .await
                .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handle = axum_server::Handle::new();
        let recording = seen.clone();
        let server = tls_server("127.0.0.1:0".parse().unwrap(), config)
            .map(move |inner| Recording {
                inner,
                seen: recording,
            })
            .handle(handle.clone())
            .serve(echo_app().into_make_service());
        let task = tokio::spawn(server);
        let addr = handle.listening().await.expect("listening");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        for _ in 0..2 {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let tls = connector.connect(name, tcp).await.expect("TLS handshake");
            ping(&format!("wss://localhost:{}/ws", addr.port()), tls).await;
        }
        assert_eq!(*seen.lock().unwrap(), vec![RELAY_NOTSENT_LOWAT; 2]);

        handle.shutdown();
        let _ = task.await;
    }
}

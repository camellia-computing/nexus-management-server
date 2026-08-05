use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::serve::Listener;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore},
};

/// Keep connection capacity larger than the request budget while bounding slow clients,
/// keep-alive sockets, and HTTP/2 connection tasks.
pub const CONNECTION_LIMIT_MULTIPLIER: usize = 4;
pub const METRICS_CONNECTION_LIMIT: usize = 64;

pub fn connection_limit(max_in_flight: usize) -> usize {
    max_in_flight
        .saturating_mul(CONNECTION_LIMIT_MULTIPLIER)
        .max(CONNECTION_LIMIT_MULTIPLIER)
}

/// Wraps an Axum listener with a connection semaphore. The permit is attached to the accepted
/// I/O object so it remains held for the complete lifetime of the spawned Axum connection task.
pub struct BoundedListener<L> {
    listener: L,
    permits: Arc<Semaphore>,
}

impl<L> BoundedListener<L> {
    pub fn new(listener: L, max_connections: usize) -> Self {
        assert!(
            max_connections > 0,
            "max_connections must be greater than zero"
        );
        Self {
            listener,
            permits: Arc::new(Semaphore::new(max_connections)),
        }
    }
}

impl<L> Listener for BoundedListener<L>
where
    L: Listener,
{
    type Io = PermitIo<L::Io>;
    type Addr = L::Addr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .expect("bounded listener semaphore is never closed");
        let (io, addr) = self.listener.accept().await;
        (
            PermitIo {
                io,
                _permit: permit,
            },
            addr,
        )
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

pub struct PermitIo<I> {
    io: I,
    _permit: OwnedSemaphorePermit,
}

impl<I> AsyncRead for PermitIo<I>
where
    I: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<I> AsyncWrite for PermitIo<I>
where
    I: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedListener, CONNECTION_LIMIT_MULTIPLIER, connection_limit};
    use axum::serve::Listener;
    use tokio::{
        net::TcpListener,
        time::{Duration, timeout},
    };

    #[test]
    fn connection_limit_scales_request_budget() {
        assert_eq!(connection_limit(1), CONNECTION_LIMIT_MULTIPLIER);
        assert_eq!(connection_limit(64), 256);
        assert_eq!(connection_limit(usize::MAX), usize::MAX);
    }

    #[tokio::test]
    async fn accept_waits_for_connection_permit_and_releases_on_io_drop() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let mut listener = BoundedListener::new(tcp, 1);
        let first_client = tokio::net::TcpStream::connect(address).await.unwrap();
        let (first_server, _) = listener.accept().await;
        let second_client = tokio::net::TcpStream::connect(address).await.unwrap();

        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        drop(first_server);
        let accepted = timeout(Duration::from_secs(1), listener.accept()).await;
        assert!(accepted.is_ok());
        drop(accepted);
        drop(first_client);
        drop(second_client);
    }
}

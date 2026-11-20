//! Stdin handling (§8.2 Stdin Controller).
//!
//! Fixed bytes are written once and the pipe is closed. A closed stdin is
//! wired to `/dev/null`-style EOF. There is no interactive PTY in phase 1
//! (§5.3).

use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use nsk_core::spec::StdinSpec;

/// Spawn the stdin writer task for a child's stdin pipe.
///
/// * [`StdinSpec::Bytes`] — write all bytes, then close.
/// * [`StdinSpec::Closed`] — drop the handle immediately (child sees EOF).
///
/// The task exits when the write completes, the pipe breaks (child died), or
/// `stop` fires.
pub fn spawn_stdin_writer<W>(
    stdin: W,
    spec: &StdinSpec,
    stop: CancellationToken,
) -> tokio::task::JoinHandle<()>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let spec = spec.clone();
    tokio::spawn(async move {
        match spec {
            StdinSpec::Closed => {
                drop(stdin);
            }
            StdinSpec::Bytes(bytes) => {
                let mut pipe = stdin;
                let write_all = async {
                    if !bytes.is_empty() && pipe.write_all(&bytes).await.is_err() {
                        return;
                    }
                    let _ = pipe.flush().await;
                    // Dropping `pipe` closes the child's stdin.
                };
                tokio::select! {
                    _ = write_all => {}
                    _ = stop.cancelled() => {
                        // Drop on cancel to avoid a stuck writer.
                    }
                }
                drop(pipe);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stdin_writer_writes_then_closes() {
        // Smoke test with an in-memory duplex pipe.
        // (Full child-pipe behavior is covered by integration tests via `cat`.)
        use tokio::io::AsyncReadExt;
        let (client, mut server) = tokio::io::duplex(8);
        let handle = spawn_stdin_writer(
            client,
            &StdinSpec::Bytes(b"hi".to_vec()),
            CancellationToken::new(),
        );
        handle.await.expect("writer task");
        let mut got = Vec::new();
        let _ = server.read_to_end(&mut got).await;
        assert_eq!(got, b"hi");
    }
}

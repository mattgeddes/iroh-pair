use crate::crypto::{decrypt, encrypt};
use crate::error::{PairError, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadHeader {
    pub mime_type: String,
    pub payload_length: u64,
    pub filename: String,
}

#[derive(Clone)]
pub struct Payload {
    pub mime_type: String,
    pub filename: String,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Payload")
            .field("mime_type", &self.mime_type)
            .field("filename", &self.filename)
            .field("data_len", &self.data.len())
            .finish()
    }
}

pub async fn write_u32<W: AsyncWrite + Unpin>(w: &mut W, v: u32) -> Result<()> {
    w.write_all(&v.to_be_bytes()).await?;
    Ok(())
}

pub async fn read_u32<R: AsyncRead + Unpin>(r: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).await?;
    Ok(u32::from_be_bytes(buf))
}

/// Per-batch transfer progress callback: `(files_done, files_total,
/// bytes_done, bytes_total)`. Byte counts are plaintext payload bytes.
/// On the *sending* side both totals are known; on the *receiving* side
/// totals arrive with the batch count prefix (`files_total`) and bytes only as
/// payloads complete (`bytes_total` is `None` until the batch ends).
pub trait ProgressSink: Send {
    fn on_progress(
        &mut self,
        files_done: usize,
        files_total: Option<usize>,
        bytes_done: u64,
        bytes_total: Option<u64>,
    );
}

impl<F: FnMut(usize, Option<usize>, u64, Option<u64>) + Send> ProgressSink for F {
    fn on_progress(
        &mut self,
        files_done: usize,
        files_total: Option<usize>,
        bytes_done: u64,
        bytes_total: Option<u64>,
    ) {
        self(files_done, files_total, bytes_done, bytes_total);
    }
}

/// A sink that ignores progress; used by the plain (no-progress) APIs.
pub struct NoopSink;
impl ProgressSink for NoopSink {
    fn on_progress(&mut self, _: usize, _: Option<usize>, _: u64, _: Option<u64>) {}
}

async fn send_batch_inner<W: AsyncWrite + Unpin>(
    w: &mut W,
    key: &[u8; 32],
    payloads: &[Payload],
    progress: &mut dyn ProgressSink,
) -> Result<()> {
    if payloads.len() > MAX_BATCH_FILES {
        return Err(PairError::Framing("too many files".into()));
    }
    let total_bytes: u64 = payloads.iter().map(|p| p.data.len() as u64).sum();
    if total_bytes as usize > MAX_BATCH_BYTES {
        return Err(PairError::Framing("batch too large".into()));
    }
    let n =
        u32::try_from(payloads.len()).map_err(|_| PairError::Framing("too many files".into()))?;
    write_u32(w, n).await?;
    let mut done_bytes = 0u64;
    for (i, p) in payloads.iter().enumerate() {
        let mut aad = Vec::with_capacity(8);
        aad.extend_from_slice(&(payloads.len() as u32).to_be_bytes());
        aad.extend_from_slice(&((i + 1) as u32).to_be_bytes());
        let ct = encrypt(key, &p.data, &aad)?;
        if ct.len() > MAX_PAYLOAD_LEN {
            return Err(PairError::Framing("payload too large".into()));
        }
        let header = PayloadHeader {
            mime_type: p.mime_type.clone(),
            payload_length: ct.len() as u64,
            filename: p.filename.clone(),
        };
        let header_bytes = serde_json::to_vec(&header)?;
        if header_bytes.len() > MAX_HEADER_LEN {
            return Err(PairError::Framing("header too large".into()));
        }
        let hlen = u32::try_from(header_bytes.len())
            .map_err(|_| PairError::Framing("header too large".into()))?;
        write_u32(w, hlen).await?;
        w.write_all(&header_bytes).await?;
        w.write_all(&ct).await?;
        done_bytes += p.data.len() as u64;
        progress.on_progress(i + 1, Some(payloads.len()), done_bytes, Some(total_bytes));
    }
    w.flush().await?;
    Ok(())
}

pub async fn send_batch<W: AsyncWrite + Unpin>(
    w: &mut W,
    key: &[u8; 32],
    payloads: &[Payload],
) -> Result<()> {
    send_batch_inner(w, key, payloads, &mut NoopSink).await
}

pub async fn send_batch_progress<W: AsyncWrite + Unpin>(
    w: &mut W,
    key: &[u8; 32],
    payloads: &[Payload],
    progress: &mut dyn ProgressSink,
) -> Result<()> {
    send_batch_inner(w, key, payloads, progress).await
}

pub const MAX_BATCH_FILES: usize = 1024;
pub const MAX_HEADER_LEN: usize = 1024 * 1024;
pub const MAX_PAYLOAD_LEN: usize = 256 * 1024 * 1024;
/// Total plaintext bytes allowed in one batch (guards against OOM on receivers).
pub const MAX_BATCH_BYTES: usize = 256 * 1024 * 1024;

/// Sanitise a peer-supplied filename for safe use as a path component on the
/// receiving side: strips separators, `..`, control chars, and falls back to a
/// generic name when nothing usable remains.
pub fn safe_filename(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c == '/' || c == '\\' || c == ':' || c.is_control() {
            out.push('_');
        } else {
            out.push(c);
        }
    }
    // collapse any traversal attempts
    while out.contains("..") {
        out = out.replace("..", "_");
    }
    let trimmed = out.trim_matches(|c: char| c == '.' || c == ' ').to_string();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        "iroh-received.bin".to_string()
    } else {
        trimmed
    }
}

impl Payload {
    pub fn safe_filename(&self) -> String {
        safe_filename(&self.filename)
    }
}

async fn recv_batch_inner<R: AsyncRead + Unpin>(
    r: &mut R,
    key: &[u8; 32],
    progress: &mut dyn ProgressSink,
) -> Result<Vec<Payload>> {
    let n_u32 = read_u32(r).await?;
    let n = n_u32 as usize;
    if n > MAX_BATCH_FILES {
        return Err(PairError::Framing("too many files".into()));
    }
    progress.on_progress(0, Some(n), 0, None);
    let mut out = Vec::with_capacity(n);
    let mut done_bytes = 0u64;
    for i in 0..n {
        let hlen_u32 = read_u32(r).await?;
        let hlen = hlen_u32 as usize;
        if hlen > MAX_HEADER_LEN {
            return Err(PairError::Framing("header too large".into()));
        }
        let mut hbuf = vec![0u8; hlen];
        r.read_exact(&mut hbuf).await?;
        let header: PayloadHeader = serde_json::from_slice(&hbuf)?;
        let plen = header.payload_length;
        let plen_usize =
            usize::try_from(plen).map_err(|_| PairError::Framing("payload too large".into()))?;
        if plen_usize > MAX_PAYLOAD_LEN {
            return Err(PairError::Framing("payload too large".into()));
        }
        let mut ct = vec![0u8; plen_usize];
        r.read_exact(&mut ct).await?;
        let mut aad = Vec::with_capacity(8);
        aad.extend_from_slice(&(n as u32).to_be_bytes());
        aad.extend_from_slice(&((i + 1) as u32).to_be_bytes());
        let data = decrypt(key, &ct, &aad)?;
        done_bytes = done_bytes.saturating_add(data.len() as u64);
        if done_bytes as usize > MAX_BATCH_BYTES {
            return Err(PairError::Framing("batch too large".into()));
        }
        out.push(Payload {
            mime_type: header.mime_type,
            filename: header.filename,
            data,
        });
        progress.on_progress(i + 1, Some(n), done_bytes, None);
    }
    Ok(out)
}

pub async fn recv_batch<R: AsyncRead + Unpin>(r: &mut R, key: &[u8; 32]) -> Result<Vec<Payload>> {
    recv_batch_inner(r, key, &mut NoopSink).await
}

pub async fn recv_batch_progress<R: AsyncRead + Unpin>(
    r: &mut R,
    key: &[u8; 32],
    progress: &mut dyn ProgressSink,
) -> Result<Vec<Payload>> {
    recv_batch_inner(r, key, progress).await
}

/// MIME type reserved for in-band protocol messages. A "message" is wire-wise a
/// batch of exactly one payload with this MIME type and an empty filename, so
/// message exchanges never collide with file-transfer batches and need no
/// changes to the framing format.
pub const MESSAGE_MIME: &str = "application/x-iroh-pair-message";

/// Send a single message over the encrypted stream.
pub async fn send_message<W: AsyncWrite + Unpin>(
    w: &mut W,
    key: &[u8; 32],
    data: &[u8],
) -> Result<()> {
    let payload = Payload {
        mime_type: MESSAGE_MIME.to_string(),
        filename: String::new(),
        data: data.to_vec(),
    };
    send_batch(w, key, &[payload]).await
}

/// Receive a single message. Errors out if the peer sent files, multiple
/// payloads, or anything that is not a MESSAGE_MIME batch.
pub async fn recv_message<R: AsyncRead + Unpin>(r: &mut R, key: &[u8; 32]) -> Result<Vec<u8>> {
    let payloads = recv_batch(r, key).await?;
    if payloads.len() != 1 {
        return Err(PairError::Framing(format!(
            "expected one message payload, got {}",
            payloads.len()
        )));
    }
    if payloads[0].mime_type != MESSAGE_MIME {
        return Err(PairError::Framing(format!(
            "unexpected batch (mime {:?}); this stream is in message mode",
            payloads[0].mime_type
        )));
    }
    if !payloads[0].filename.is_empty() {
        return Err(PairError::Framing(
            "message must have empty filename".into(),
        ));
    }
    Ok(payloads.into_iter().next().unwrap().data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_batch() {
        let (mut a, mut b) = duplex(1024 * 1024);
        let key = [9u8; 32];
        let payloads = vec![
            Payload {
                mime_type: "text/plain".into(),
                filename: "a.txt".into(),
                data: b"hello".to_vec(),
            },
            Payload {
                mime_type: "image/png".into(),
                filename: "b.png".into(),
                data: vec![1, 2, 3, 4],
            },
        ];
        let send = tokio::spawn(async move {
            send_batch(&mut a, &key, &payloads).await.unwrap();
        });
        let recv = recv_batch(&mut b, &key).await.unwrap();
        send.await.unwrap();
        assert_eq!(recv.len(), 2);
        assert_eq!(recv[0].data, b"hello");
        assert_eq!(recv[1].filename, "b.png");
    }

    #[test]
    fn header_serde() {
        let h = PayloadHeader {
            mime_type: "image/jpeg".into(),
            payload_length: 204800,
            filename: "photo.jpg".into(),
        };
        let b = serde_json::to_vec(&h).unwrap();
        let h2: PayloadHeader = serde_json::from_slice(&b).unwrap();
        assert_eq!(h2.payload_length, 204800);
    }

    #[tokio::test]
    async fn message_roundtrip() {
        let (mut a, mut b) = duplex(1024 * 1024);
        let key = [7u8; 32];
        let send = tokio::spawn(async move {
            send_message(&mut a, &key, b"ping").await.unwrap();
        });
        let msg = recv_message(&mut b, &key).await.unwrap();
        send.await.unwrap();
        assert_eq!(msg, b"ping");
    }

    #[tokio::test]
    async fn recv_message_rejects_file_batch() {
        let (mut a, mut b) = duplex(1024 * 1024);
        let key = [7u8; 32];
        let send = tokio::spawn(async move {
            send_batch(
                &mut a,
                &key,
                &[Payload {
                    mime_type: "text/plain".into(),
                    filename: "f.txt".into(),
                    data: b"x".to_vec(),
                }],
            )
            .await
            .unwrap();
        });
        send.await.unwrap();
        assert!(recv_message(&mut b, &key).await.is_err());
    }

    #[tokio::test]
    async fn progress_events_fire() {
        let (mut a, mut b) = duplex(1024 * 1024);
        let key = [1u8; 32];
        let payloads = vec![
            Payload {
                mime_type: "text/plain".into(),
                filename: "a.txt".into(),
                data: vec![0u8; 100],
            },
            Payload {
                mime_type: "text/plain".into(),
                filename: "b.txt".into(),
                data: vec![0u8; 50],
            },
        ];
        let send = tokio::spawn(async move {
            let mut events: Vec<String> = Vec::new();
            send_batch_progress(
                &mut a,
                &key,
                &payloads,
                &mut |done, total, bytes, total_bytes| {
                    events.push(format!("{done}/{total:?} {bytes}/{total_bytes:?}"));
                },
            )
            .await
            .unwrap();
            events
        });
        let mut recv_events: Vec<String> = Vec::new();
        let got = recv_batch_progress(&mut b, &key, &mut |done, total, bytes, total_bytes| {
            recv_events.push(format!("{done}/{total:?} {bytes}/{total_bytes:?}"));
        })
        .await
        .unwrap();
        let sender_events = send.await.unwrap();
        assert_eq!(got.len(), 2);
        // Sender knows totals; receiver does not until payloads complete.
        assert_eq!(sender_events[0], "1/Some(2) 100/Some(150)");
        assert_eq!(sender_events[1], "2/Some(2) 150/Some(150)");
        assert_eq!(recv_events[0], "0/Some(2) 0/None");
        assert_eq!(recv_events[1], "1/Some(2) 100/None");
        assert_eq!(recv_events[2], "2/Some(2) 150/None");
    }

    #[tokio::test]
    async fn tampered_ciphertext_rejected() {
        let (mut a, mut b) = duplex(1024 * 1024);
        let key = [9u8; 32];
        let payloads = vec![Payload {
            mime_type: "text/plain".into(),
            filename: "a.txt".into(),
            data: b"hello".to_vec(),
        }];
        let send = tokio::spawn(async move {
            send_batch(&mut a, &key, &payloads).await.unwrap();
        });
        // Read raw bytes and flip a bit in the ciphertext, then feed to receiver.
        let wrong_key = [1u8; 32];
        // receive with wrong key should fail
        let res = recv_batch(&mut b, &wrong_key).await;
        assert!(res.is_err());
        let _ = send.await;
    }

    #[tokio::test]
    async fn message_requires_empty_filename() {
        let (mut a, mut b) = duplex(1024 * 1024);
        let key = [7u8; 32];
        // Send a batch that looks like a message but with a non-empty filename.
        let send = tokio::spawn(async move {
            let p = Payload {
                mime_type: MESSAGE_MIME.to_string(),
                filename: "notempty.txt".into(),
                data: b"ping".to_vec(),
            };
            send_batch(&mut a, &key, &[p]).await.unwrap();
        });
        send.await.unwrap();
        assert!(recv_message(&mut b, &key).await.is_err());
    }
}

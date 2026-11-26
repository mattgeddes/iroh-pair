use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot, Semaphore};

use crate::crypto::{
    derive_directional_keys, dh, generate_keypair, sas_from_transcript, transcript, ALPN,
};
use crate::error::{PairError, Result};
use crate::framing::{
    recv_batch, recv_batch_progress, recv_message, send_batch, send_batch_progress, send_message,
    Payload, ProgressSink,
};
use x25519_dalek::PublicKey;

pub const ALPN_BYTES: &[u8] = ALPN;

/// Default per-leg timeout for exchange/message round-trips. Each individual
/// leg (one side sending one turn, the other receiving it) must complete
/// within this budget or the operation returns `PairError::Timeout`.
pub const DEFAULT_LEG_TIMEOUT: Duration = Duration::from_secs(120);

/// Runs `fut` under the per-leg timeout, flattening the timeout layer into the
/// inner `Result` (the futures passed here all resolve to `Result<T>`).
async fn with_leg_timeout<T, F: std::future::Future<Output = Result<T>>>(fut: F) -> Result<T> {
    match tokio::time::timeout(DEFAULT_LEG_TIMEOUT, fut).await {
        Ok(res) => res,
        Err(_) => Err(PairError::Timeout(DEFAULT_LEG_TIMEOUT)),
    }
}

#[derive(Clone)]
pub struct PairingProtocol {
    pub enabled: Arc<AtomicBool>,
    incoming_tx: mpsc::Sender<IncomingPairing>,
    local_id: Arc<Mutex<Option<iroh::EndpointId>>>,
    admission: Arc<Semaphore>,
}

impl std::fmt::Debug for PairingProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingProtocol").finish()
    }
}

impl PairingProtocol {
    pub fn new() -> (Self, mpsc::Receiver<IncomingPairing>) {
        let (tx, rx) = mpsc::channel(16);
        let p = Self {
            enabled: Arc::new(AtomicBool::new(false)),
            incoming_tx: tx,
            local_id: Arc::new(Mutex::new(None)),
            admission: Arc::new(Semaphore::new(16)),
        };
        (p, rx)
    }

    /// Set the endpoint's own identity once the endpoint is bound, so the
    /// pairing transcript can bind to it (see crypto::transcript).
    pub fn set_local_id(&self, id: iroh::EndpointId) {
        *self.local_id.lock().unwrap() = Some(id);
    }

    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }
}

impl ProtocolHandler for PairingProtocol {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        if !self.enabled.load(Ordering::SeqCst) {
            connection.close(0u32.into(), b"not pairing");
            return Ok(());
        }
        // Admission control: bound concurrent handshakes.
        let permit = match self.admission.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                connection.close(0u32.into(), b"busy");
                return Ok(());
            }
        };
        let local_id = match *self.local_id.lock().unwrap() {
            Some(id) => id,
            None => {
                connection.close(0u32.into(), b"no local id");
                return Ok(());
            }
        };
        let remote_id = connection.remote_id();
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(AcceptError::from_err)?;

        // Commitment round: learn the initiator's commitment before revealing ours.
        let mut commit_buf = [0u8; 32];
        recv.read_exact(&mut commit_buf)
            .await
            .map_err(AcceptError::from_err)?;
        let initiator_commit = commit_buf;

        let (rsk, rpk) = generate_keypair();
        let responder_commit = blake3::hash(rpk.as_bytes());
        send.write_all(responder_commit.as_bytes())
            .await
            .map_err(AcceptError::from_err)?;
        send.flush().await.map_err(AcceptError::from_err)?;

        // Now exchange public keys, verifying commitments.
        let mut pk_buf = [0u8; 32];
        recv.read_exact(&mut pk_buf)
            .await
            .map_err(AcceptError::from_err)?;
        let initiator_pk_bytes = pk_buf;
        if *blake3::hash(&initiator_pk_bytes).as_bytes() != initiator_commit {
            connection.close(0u32.into(), b"bad commitment");
            return Ok(());
        }

        send.write_all(rpk.as_bytes())
            .await
            .map_err(AcceptError::from_err)?;
        send.flush().await.map_err(AcceptError::from_err)?;

        let remote_pk = PublicKey::from(initiator_pk_bytes);
        let shared = match dh(&rsk, &remote_pk) {
            Ok(s) => s,
            Err(_) => {
                connection.close(0u32.into(), b"bad key");
                return Ok(());
            }
        };
        let transcript_bytes = transcript(
            &initiator_pk_bytes,
            rpk.as_bytes(),
            remote_id.as_bytes(),
            local_id.as_bytes(),
        );
        let sas = sas_from_transcript(&transcript_bytes);
        let (i2r, r2i) = derive_directional_keys(&shared, &transcript_bytes);

        let (done_tx, done_rx) = oneshot::channel();
        let pairing = IncomingPairing {
            sas,
            remote_id,
            transcript: transcript_bytes,
            send_key: r2i,
            recv_key: i2r,
            send: Some(send),
            recv: Some(recv),
            done: Some(done_tx),
            confirmed: false,
            failed: false,
            finished: false,
        };
        if self.incoming_tx.try_send(pairing).is_err() {
            connection.close(0u32.into(), b"busy");
            return Ok(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(60), done_rx).await;
        drop(permit);
        Ok(())
    }
}

pub struct IncomingPairing {
    pub sas: u32,
    pub remote_id: iroh::EndpointId,
    pub transcript: [u8; 32],
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send: Option<iroh::endpoint::SendStream>,
    recv: Option<iroh::endpoint::RecvStream>,
    done: Option<oneshot::Sender<()>>,
    confirmed: bool,
    failed: bool,
    finished: bool,
}

impl IncomingPairing {
    pub async fn confirm(&mut self) -> Result<()> {
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        if self.confirmed {
            return Ok(());
        }
        // Responder reads first, then writes (asymmetric to avoid deadlock).
        let recv = self.recv.as_mut().ok_or(PairError::ChannelClosed)?;
        let payloads = recv_batch(recv, &self.recv_key).await?;
        if !payloads.is_empty() {
            self.failed = true;
            return Err(PairError::Handshake(
                "unexpected data during confirmation".into(),
            ));
        }
        let send = self.send.as_mut().ok_or(PairError::ChannelClosed)?;
        send.write_all(&0u32.to_be_bytes())
            .await
            .map_err(|e| PairError::Iroh(e.to_string()))?;
        send.flush()
            .await
            .map_err(|e| PairError::Iroh(e.to_string()))?;
        self.confirmed = true;
        Ok(())
    }
    pub async fn receive_batch(&mut self) -> Result<Vec<Payload>> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        let recv = self.recv.as_mut().ok_or(PairError::ChannelClosed)?;
        recv_batch(recv, &self.recv_key).await
    }
    /// Like [`receive_batch`](Self::receive_batch) but reports per-payload
    /// progress to `sink` (bytes counted as plaintext; the total byte size is
    /// not known until payloads complete, so `files_total` is known after the
    /// count prefix but `bytes_total` stays `None`).
    pub async fn receive_batch_progress(
        &mut self,
        sink: &mut dyn ProgressSink,
    ) -> Result<Vec<Payload>> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        let recv = self.recv.as_mut().ok_or(PairError::ChannelClosed)?;
        recv_batch_progress(recv, &self.recv_key, sink).await
    }
    pub async fn send_batch(&mut self, payloads: &[Payload]) -> Result<()> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        let send = self.send.as_mut().ok_or(PairError::ChannelClosed)?;
        send_batch(send, &self.send_key, payloads).await
    }
    /// Like [`send_batch`](Self::send_batch) but reports per-payload progress
    /// to `sink` (sender knows both totals up front).
    pub async fn send_batch_progress(
        &mut self,
        payloads: &[Payload],
        sink: &mut dyn ProgressSink,
    ) -> Result<()> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        let send = self.send.as_mut().ok_or(PairError::ChannelClosed)?;
        send_batch_progress(send, &self.send_key, payloads, sink).await
    }
    /// Bidirectional use-case, responder side: waits for the initiator's
    /// request (taking the first turn), sends `reply` back, and returns the
    /// request payloads. Legs are bounded by [`DEFAULT_LEG_TIMEOUT`].
    pub async fn respond(&mut self, reply: &[Payload]) -> Result<Vec<Payload>> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        let request = with_leg_timeout(self.receive_batch()).await?;
        with_leg_timeout(self.send_batch(reply)).await?;
        Ok(request)
    }
    /// Send one message on this leg (see [`crate::framing::MESSAGE_MIME`]).
    pub async fn send_message(&mut self, data: &[u8]) -> Result<()> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        let send = self.send.as_mut().ok_or(PairError::ChannelClosed)?;
        with_leg_timeout(send_message(send, &self.send_key, data)).await
    }
    /// Receive one message on this leg. Errors on file batches / wrong MIME.
    pub async fn receive_message(&mut self) -> Result<Vec<u8>> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        let recv = self.recv.as_mut().ok_or(PairError::ChannelClosed)?;
        with_leg_timeout(recv_message(recv, &self.recv_key)).await
    }
    /// Message-flavoured shortcut for [`respond`](Self::respond): receive the
    /// request message, send `reply`, return the request bytes.
    pub async fn respond_message(&mut self, reply: &[u8]) -> Result<Vec<u8>> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        let request = self.receive_message().await?;
        self.send_message(reply).await?;
        Ok(request)
    }
    pub fn finish(&mut self) {
        self.finished = true;
        if let Some(tx) = self.done.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for IncomingPairing {
    fn drop(&mut self) {
        if let Some(tx) = self.done.take() {
            let _ = tx.send(());
        }
    }
}

// Initiator side
pub struct InitiatorSession {
    pub sas: u32,
    pub remote_id: iroh::EndpointId,
    pub transcript: [u8; 32],
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send: Option<iroh::endpoint::SendStream>,
    recv: Option<iroh::endpoint::RecvStream>,
    _conn: iroh::endpoint::Connection,
    confirmed: bool,
    failed: bool,
    finished: bool,
}

impl InitiatorSession {
    pub async fn confirm(&mut self) -> Result<()> {
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        if self.confirmed {
            return Ok(());
        }
        // Initiator writes first, then reads (asymmetric to avoid deadlock).
        let send = self.send.as_mut().ok_or(PairError::ChannelClosed)?;
        send.write_all(&0u32.to_be_bytes())
            .await
            .map_err(|e| PairError::Iroh(e.to_string()))?;
        send.flush()
            .await
            .map_err(|e| PairError::Iroh(e.to_string()))?;
        let recv = self.recv.as_mut().ok_or(PairError::ChannelClosed)?;
        let payloads = recv_batch(recv, &self.recv_key).await?;
        if !payloads.is_empty() {
            self.failed = true;
            return Err(PairError::Handshake(
                "unexpected data during confirmation".into(),
            ));
        }
        self.confirmed = true;
        Ok(())
    }
    pub async fn send_batch(&mut self, payloads: &[Payload]) -> Result<()> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        let send = self.send.as_mut().ok_or(PairError::ChannelClosed)?;
        send_batch(send, &self.send_key, payloads).await
    }
    /// Like [`send_batch`](Self::send_batch) but reports per-payload progress
    /// to `sink` (sender knows both totals up front).
    pub async fn send_batch_progress(
        &mut self,
        payloads: &[Payload],
        sink: &mut dyn ProgressSink,
    ) -> Result<()> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        let send = self.send.as_mut().ok_or(PairError::ChannelClosed)?;
        send_batch_progress(send, &self.send_key, payloads, sink).await
    }
    pub async fn receive_batch(&mut self) -> Result<Vec<Payload>> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        let recv = self.recv.as_mut().ok_or(PairError::ChannelClosed)?;
        recv_batch(recv, &self.recv_key).await
    }
    /// Like [`receive_batch`](Self::receive_batch) but reports per-payload
    /// progress to `sink` (receiver learns the file count from the count
    /// prefix; `bytes_total` stays `None` until the batch ends).
    pub async fn receive_batch_progress(
        &mut self,
        sink: &mut dyn ProgressSink,
    ) -> Result<Vec<Payload>> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        let recv = self.recv.as_mut().ok_or(PairError::ChannelClosed)?;
        recv_batch_progress(recv, &self.recv_key, sink).await
    }
    /// Bidirectional use-case, initiator side: sends `request` (taking the
    /// first turn), then waits for and returns the responder's reply. Legs are
    /// bounded by [`DEFAULT_LEG_TIMEOUT`].
    pub async fn exchange(&mut self, request: &[Payload]) -> Result<Vec<Payload>> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        with_leg_timeout(self.send_batch(request)).await?;
        with_leg_timeout(self.receive_batch()).await
    }
    /// Send one message on this leg (see [`crate::framing::MESSAGE_MIME`]).
    pub async fn send_message(&mut self, data: &[u8]) -> Result<()> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        let send = self.send.as_mut().ok_or(PairError::ChannelClosed)?;
        with_leg_timeout(send_message(send, &self.send_key, data)).await
    }
    /// Receive one message on this leg. Errors on file batches / wrong MIME.
    pub async fn receive_message(&mut self) -> Result<Vec<u8>> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        let recv = self.recv.as_mut().ok_or(PairError::ChannelClosed)?;
        with_leg_timeout(recv_message(recv, &self.recv_key)).await
    }
    /// Message-flavoured shortcut for [`exchange`](Self::exchange): send the
    /// request message, wait for and return the reply bytes.
    pub async fn exchange_message(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        if !self.confirmed {
            return Err(PairError::Handshake("not confirmed".into()));
        }
        if self.failed || self.finished {
            return Err(PairError::Handshake("session not usable".into()));
        }
        self.send_message(request).await?;
        self.receive_message().await
    }
    pub async fn finish_send(&mut self) -> Result<()> {
        if let Some(s) = self.send.as_mut() {
            s.finish().map_err(|e| PairError::Iroh(e.to_string()))?;
        }
        self.finished = true;
        Ok(())
    }
    pub async fn wait_closed(self) {
        let _ = tokio::time::timeout(Duration::from_secs(30), self._conn.closed()).await;
    }
    pub async fn close(mut self) -> Result<()> {
        if let Some(mut s) = self.send.take() {
            let _ = s.finish();
        }
        self._conn.close(0u32.into(), b"done");
        Ok(())
    }
}

pub async fn initiator_connect(
    endpoint: &iroh::Endpoint,
    remote: impl Into<iroh::EndpointAddr>,
) -> Result<InitiatorSession> {
    use crate::crypto::generate_keypair;
    let remote_addr: iroh::EndpointAddr = remote.into();
    let responder_id = remote_addr.id;
    let initiator_id = endpoint.id();
    let conn = endpoint
        .connect(remote_addr, ALPN)
        .await
        .map_err(|e| PairError::Iroh(e.to_string()))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| PairError::Iroh(e.to_string()))?;

    let (isk, ipk) = generate_keypair();

    // Commitment round: commit to our public key before revealing it.
    let initiator_commit = blake3::hash(ipk.as_bytes());
    send.write_all(initiator_commit.as_bytes())
        .await
        .map_err(|e| PairError::Iroh(e.to_string()))?;
    send.flush()
        .await
        .map_err(|e| PairError::Iroh(e.to_string()))?;

    let mut commit_buf = [0u8; 32];
    recv.read_exact(&mut commit_buf)
        .await
        .map_err(|e| PairError::Iroh(e.to_string()))?;
    let responder_commit = commit_buf;

    send.write_all(ipk.as_bytes())
        .await
        .map_err(|e| PairError::Iroh(e.to_string()))?;
    send.flush()
        .await
        .map_err(|e| PairError::Iroh(e.to_string()))?;

    let mut pk_buf = [0u8; 32];
    recv.read_exact(&mut pk_buf)
        .await
        .map_err(|e| PairError::Iroh(e.to_string()))?;
    let responder_pk_bytes = pk_buf;
    if *blake3::hash(&responder_pk_bytes).as_bytes() != responder_commit {
        conn.close(0u32.into(), b"bad commitment");
        return Err(PairError::Handshake("responder commitment mismatch".into()));
    }
    let responder_pk = PublicKey::from(responder_pk_bytes);

    let shared = dh(&isk, &responder_pk)?;
    let transcript_bytes = transcript(
        ipk.as_bytes(),
        &responder_pk_bytes,
        initiator_id.as_bytes(),
        responder_id.as_bytes(),
    );
    let sas = sas_from_transcript(&transcript_bytes);
    let (i2r, r2i) = derive_directional_keys(&shared, &transcript_bytes);

    Ok(InitiatorSession {
        sas,
        remote_id: responder_id,
        transcript: transcript_bytes,
        send_key: i2r,
        recv_key: r2i,
        send: Some(send),
        recv: Some(recv),
        _conn: conn,
        confirmed: false,
        failed: false,
        finished: false,
    })
}

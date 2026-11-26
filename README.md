# iroh-pair

Ephemeral P2P pairing and multi-file transfer over Iroh.

ALPN: `iroh-pair/1`.

## Features

- X25519 handshake with BLAKE3 transcript hashing and 24-bit SAS.
- Directional session keys (initiator->responder and responder->initiator) to avoid
  nonce reuse.
- AEAD (ChaCha20Poly1305) with a random 12-byte nonce prepended to every message.
- Multi-file batched transfer with MIME metadata.
- Bidirectional message exchange (initiator talks first, responder replies), with
  per-leg timeouts.

## Bidirectional exchange

A session is a series of encrypted *turns* on one stream: each turn is one side
sending one batch (batch-count-prefixed) and the other side receiving it. The
initiator always takes the first turn, so peers never collide:

```rust
// initiator
let request = vec![Payload { mime_type: "text/plain".into(), filename: "".into(), data: b"hello".to_vec() }];
let reply = session.exchange(&request).await?;

// responder (after SAS confirmation)
let request = pairing.respond(&reply_batch).await?; // returns the request, sends the reply
pairing.finish();
```

Small-payload convenience layer (same stream, same framing):

```rust
// initiator
let reply: Vec<u8> = session.exchange_message(b"ping").await?;

// responder
let request: Vec<u8> = pairing.respond_message(b"pong").await?;
```

Framing conventions:

- A "message" is wire-wise a batch of exactly one payload with MIME type
  `application/x-iroh-pair-message` (`iroh_pair::MESSAGE_MIME`) and an empty
  filename, so no wire-format change was needed; existing peers interoperate.
- Both `exchange`/`respond` and the message helpers bound every leg with
  `iroh_pair::DEFAULT_LEG_TIMEOUT` (120 s); an untimely turn returns
  `PairError::Timeout` instead of blocking forever. The longer-horizon file
  batch APIs (`send_batch`/`receive_batch`) are intentionally unbounded: they
  may legitimately exceed the leg timeout for large payloads.
- Sides must take turns. Sending two turns back-to-back without the peer
  receiving in between deadlocks by construction (the receiver reads one batch
  at a time).

## Notes for platform bindings

- `recv_batch` returns file bytes in memory; callers (Android, etc.) are responsible
  for persisting them using platform-appropriate storage semantics.
- SAS is an out-of-band value: the crate does not transmit confirmation. The
  application must display it and only call `send_batch`/`receive_batch` after
  the user confirms a match.
- Discovery is out of scope; provide an `EndpointId` (and optional relay URL) to
  `initiator_connect`.
- CLI demo: `cargo run --example cli -- exchange-responder --reply "hi"` and
  `cargo run --example cli -- exchange-initiator --endpoint-id <id> --message "hey"`
  exercise the message leg end-to-end between two nodes.
use iroh::endpoint::presets;
use iroh_pair::{initiator_connect, PairingProtocol, Payload, MESSAGE_MIME};

#[tokio::test]
async fn end_to_end_transfer() {
    let responder_ep = iroh::Endpoint::bind(presets::N0).await.unwrap();
    let (protocol, mut incoming_rx) = PairingProtocol::new();
    protocol.set_local_id(responder_ep.id());
    protocol.enable();
    let router = iroh::protocol::Router::builder(responder_ep.clone())
        .accept(iroh_pair::ALPN, protocol.clone())
        .spawn();

    let initiator_ep = iroh::Endpoint::bind(presets::N0).await.unwrap();
    let remote = responder_ep.addr();
    let mut session = initiator_connect(&initiator_ep, remote).await.unwrap();

    let payloads = vec![Payload {
        mime_type: "text/plain".into(),
        filename: "hello.txt".into(),
        data: b"hello world".to_vec(),
    }];
    // Responder runs concurrently so confirmation can complete.
    let sas = session.sas;
    let responder_task = tokio::spawn(async move {
        if let Some(mut pairing) = incoming_rx.recv().await {
            assert_eq!(pairing.sas, sas);
            pairing.confirm().await.unwrap();
            let received = pairing.receive_batch().await.unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].data, b"hello world");
            pairing.finish();
        }
    });

    session.confirm().await.unwrap();
    session.send_batch(&payloads).await.unwrap();
    session.finish_send().await.unwrap();

    responder_task.await.unwrap();

    session.wait_closed().await;
    router.shutdown().await.unwrap();
}

fn payload(name: &str, mime: &str, data: &[u8]) -> Payload {
    Payload {
        mime_type: mime.into(),
        filename: name.into(),
        data: data.to_vec(),
    }
}

#[tokio::test]
async fn end_to_end_batch_exchange() {
    let responder_ep = iroh::Endpoint::bind(presets::N0).await.unwrap();
    let (protocol, mut incoming_rx) = PairingProtocol::new();
    protocol.set_local_id(responder_ep.id());
    protocol.enable();
    let router = iroh::protocol::Router::builder(responder_ep.clone())
        .accept(iroh_pair::ALPN, protocol.clone())
        .spawn();

    let initiator_ep = iroh::Endpoint::bind(presets::N0).await.unwrap();
    let remote = responder_ep.addr();
    let mut session = initiator_connect(&initiator_ep, remote).await.unwrap();
    let sas = session.sas;

    let request = vec![payload("req.txt", "text/plain", b"please")];
    let spawned = tokio::spawn(async move {
        session.confirm().await.unwrap();
        let reply = session.exchange(&request).await.unwrap();
        reply
    });

    let mut pairing = incoming_rx.recv().await.unwrap();
    assert_eq!(pairing.sas, sas);
    pairing.confirm().await.unwrap();
    let reply = vec![payload("rep.txt", "text/plain", b"granted")];
    let request = pairing.respond(&reply).await.unwrap();
    assert_eq!(request.len(), 1);
    assert_eq!(request[0].data, b"please");
    pairing.finish();

    let reply = spawned.await.unwrap();
    assert_eq!(reply.len(), 1);
    assert_eq!(reply[0].data, b"granted");
    assert_eq!(reply[0].mime_type, "text/plain");

    router.shutdown().await.unwrap();
}

/// Two full exchange rounds on the same stream, plus a message-leg each way,
/// to prove turn-taking works with the batch count prefix.
#[tokio::test]
async fn end_to_end_message_exchange_multiple_rounds() {
    let responder_ep = iroh::Endpoint::bind(presets::N0).await.unwrap();
    let (protocol, mut incoming_rx) = PairingProtocol::new();
    protocol.set_local_id(responder_ep.id());
    protocol.enable();
    let router = iroh::protocol::Router::builder(responder_ep.clone())
        .accept(iroh_pair::ALPN, protocol.clone())
        .spawn();

    let initiator_ep = iroh::Endpoint::bind(presets::N0).await.unwrap();
    let remote = responder_ep.addr();
    let mut session = initiator_connect(&initiator_ep, remote).await.unwrap();

    // Round 1 + round 2 on the initiator side.
    let spawned = tokio::spawn(async move {
        session.confirm().await.unwrap();
        let ack1 = session.exchange_message(b"ping-1").await.unwrap();
        assert_eq!(ack1, b"pong-1");
        let reply = session.exchange_message(b"ping-2").await.unwrap();
        assert_eq!(reply, b"pong-2");
        // A message leg in the other direction too (responder -> initiator).
        let pushed = session.receive_message().await.unwrap();
        assert_eq!(pushed, b"S:pushed");
    });

    let mut pairing = incoming_rx.recv().await.unwrap();
    pairing.confirm().await.unwrap();
    let req = pairing.respond_message(b"pong-1").await.unwrap();
    assert_eq!(req, b"ping-1");
    let req = pairing.respond_message(b"pong-2").await.unwrap();
    assert_eq!(req, b"ping-2");
    pairing.send_message(b"S:pushed").await.unwrap();
    pairing.finish();

    spawned.await.unwrap();

    // Message framing is a batch of one with the reserved MIME type and no
    // filename — verify the convention holds on the raw batch layer.
    assert_eq!(MESSAGE_MIME, "application/x-iroh-pair-message");

    router.shutdown().await.unwrap();
}

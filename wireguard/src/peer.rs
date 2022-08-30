use crate::wire;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};

pub struct Peer {
    public_key: [u8; 32],
    sessions: [PeerSession; 3],
    current: usize,
}

// todo put keys into something that zeroes out
pub struct PeerSession {
    ephemeral_private: [u8; 32],
    ephemeral_public: [u8; 32],
    psk: [u8; 32],
    hash: [u8; 32],
    chaining: [u8; 32],
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    // not needed the way this is currently implemented
    _rx_nonce: u64,
    tx_nonce: u64,
    index: u32,
}

pub struct Capabilities {
    active: bool,
    can_send_handshake_initiation: bool,
    can_receive_handshake_response: bool,
    can_receive_handshake_initiation: bool,
}

pub struct EncodeDecodeCapability {}

pub struct SendHandshakeInitiationCapability {}

pub struct ReceiveHandshakeInitiationCapability {}

pub struct ReceiveHandshakeResponseCapability {}

impl Peer {
    pub fn enumerate_capabilities(&self) -> Capabilities {
        todo!()
    }

    pub fn next(&self) -> usize {
        (self.current + 1) % 3
    }
}

impl Capabilities {
    pub fn encode_decode(&self) -> Option<EncodeDecodeCapability> {
        if self.active {
            Some(EncodeDecodeCapability {})
        } else {
            None
        }
    }

    pub fn send_handshake_initiation(&self) -> Option<SendHandshakeInitiationCapability> {
        if self.can_send_handshake_initiation {
            Some(SendHandshakeInitiationCapability {})
        } else {
            None
        }
    }

    pub fn receive_handshake_response(&self) -> Option<ReceiveHandshakeResponseCapability> {
        if self.can_receive_handshake_response {
            Some(ReceiveHandshakeResponseCapability {})
        } else {
            None
        }
    }

    pub fn receive_handshake_initiation(&self) -> Option<ReceiveHandshakeInitiationCapability> {
        if self.can_receive_handshake_initiation {
            Some(ReceiveHandshakeInitiationCapability {})
        } else {
            None
        }
    }
}

impl EncodeDecodeCapability {
    pub fn encode(&self, peer: &mut Peer, headers: &mut [u8], packet: &mut Vec<u8>) {
        let current_session = &mut peer.sessions[peer.current];

        // apply padding to packet to make this a multiple of 16
        // this would be simpler if div_ceil were stable!!!
        let padding_amount = 16 * ((packet.len() + 16 - 1) / 16) - packet.len();
        packet.resize(packet.len() + padding_amount, 0);

        // encrypt
        seal_aead(
            &current_session.tx_key,
            current_session.tx_nonce,
            packet,
            &[],
        );

        // set header fields
        let mut msg_headers = wire::TransportData::new(headers);
        *msg_headers.ty_mut() = 0x04;
        *msg_headers.receiver_mut() = current_session.index.to_le_bytes();
        *msg_headers.counter_mut() = current_session.tx_nonce.to_le_bytes();

        // advance the nonce counter
        peer.sessions[peer.current].tx_nonce += 1;
    }

    pub fn decode(&self, peer: &mut Peer, headers: &[u8], packet: &mut Vec<u8>) -> bool {
        let current_session = &mut peer.sessions[peer.current];

        let msg_headers = wire::TransportData::new(headers);

        let nonce = u64::from_le_bytes(*msg_headers.counter());

        unseal_aead(&current_session.rx_key, nonce, packet, &[])
    }
}

impl SendHandshakeInitiationCapability {
    pub fn generate(self, _peer: &mut Peer, _packet: &mut [u8]) {
        todo!()
    }
}

impl ReceiveHandshakeInitiationCapability {
    pub fn consume(self, _peer: &mut Peer, _packet: &mut [u8]) {
        todo!()
    }
}

impl ReceiveHandshakeResponseCapability {
    pub fn consume(self, _peer: &mut Peer, _packet: &mut [u8]) {
        todo!()
    }
}

fn unseal_aead(key: &[u8; 32], counter: u64, plaintext: &mut Vec<u8>, auth: &[u8]) -> bool {
    let key = Key::from_slice(key);

    let chacha = ChaCha20Poly1305::new(key);

    let mut nonce = [0u8; 12];
    nonce[4..].clone_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce);

    chacha.decrypt_in_place(nonce, auth, plaintext).is_ok()
}

fn seal_aead(key: &[u8; 32], counter: u64, plaintext: &mut Vec<u8>, auth: &[u8]) {
    let key = Key::from_slice(key);

    let chacha = ChaCha20Poly1305::new(key);

    let mut nonce = [0u8; 12];
    nonce[4..].clone_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce);

    chacha.encrypt_in_place(nonce, auth, plaintext).unwrap();
}

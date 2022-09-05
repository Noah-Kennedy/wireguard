use crate::wire;
use x25519_dalek::{PublicKey, ReusableSecret};

mod crypto;

use crypto::*;

const SESSIONS: usize = 3;
const CONSTRUCTION: &[u8; 37] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8; 34] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

pub struct Peer {
    public_key: [u8; 32],
    handshake: Option<Box<Handshake>>,
    sessions: [Option<Box<PeerSession>>; SESSIONS],
    current: usize,
    index: u32,
}

struct PeerSession {
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    // not needed the way this is currently implemented
    _rx_nonce: u64,
    tx_nonce: u64,
    tx_index: u32,
}

struct Handshake {
    ephemeral_private: ReusableSecret,
    ephemeral_public: [u8; 32],
    psk: [u8; 32],
    hash: [u8; 32],
    chaining: [u8; 32],
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    // not needed the way this is currently implemented
    _rx_nonce: u64,
    tx_nonce: u64,
    tx_index: u32,
}

impl Handshake {
    fn new(ephemeral_private: ReusableSecret) -> Self {
        Self {
            ephemeral_private,
            ephemeral_public: [0; 32],
            psk: [0; 32],
            hash: [0; 32],
            chaining: [0; 32],
            tx_key: [0; 32],
            rx_key: [0; 32],
            _rx_nonce: 0,
            tx_nonce: 0,
            tx_index: 0,
        }
    }
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

    pub fn initiate_handshake(&mut self, static_public: &[u8; 32], packet: &mut [u8]) {
        self.handshake = Some(Box::new(Handshake::new(dh_generate())));

        let handshake = self.handshake.as_mut().unwrap();

        hash(&[CONSTRUCTION], &mut handshake.chaining);

        let mut temp = [0; 32];
        hash(&[&handshake.chaining, IDENTIFIER], &mut temp);
        hash(&[&temp, &self.public_key], &mut handshake.hash);

        let mut msg = wire::HandshakeInitiation::new(packet);

        *msg.ty_mut() = 0x01;
        *msg.reserved_mut() = [0; 3];
        *msg.sender_mut() = self.index.to_le_bytes();

        *msg.ephemeral_mut() = PublicKey::from(&handshake.ephemeral_private).to_bytes();
    }

    fn encode(&mut self, headers: &mut [u8], packet: &mut Vec<u8>) {
        let current_session = self.sessions[self.current].as_mut().unwrap();

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
        *msg_headers.receiver_mut() = current_session.tx_index.to_le_bytes();
        *msg_headers.counter_mut() = current_session.tx_nonce.to_le_bytes();

        // advance the nonce counter
        current_session.tx_nonce += 1;
    }

    fn decode(&mut self, headers: &[u8], packet: &mut Vec<u8>) -> bool {
        let current_session = self.sessions[self.current].as_mut().unwrap();

        let msg_headers = wire::TransportData::new(headers);

        let nonce = u64::from_le_bytes(*msg_headers.counter());

        unseal_aead(&current_session.rx_key, nonce, packet, &[])
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
        peer.encode(headers, packet)
    }

    pub fn decode(&self, peer: &mut Peer, headers: &[u8], packet: &mut Vec<u8>) -> bool {
        peer.decode(headers, packet)
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

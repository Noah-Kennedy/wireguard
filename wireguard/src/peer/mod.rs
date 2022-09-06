use crate::wire;
use x25519_dalek::{PublicKey, ReusableSecret};

mod crypto;

#[cfg(test)]
mod tests;

use crate::wire::HandshakeInitiation;
use crypto::*;

const SESSIONS: usize = 3;
const CONSTRUCTION: &[u8; 37] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8; 34] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8; 8] = b"mac1----";

pub struct Peer {
    sessions: [Option<Box<PeerSession>>; SESSIONS],
    public_key: PublicKey,
    handshake: Option<Box<Handshake>>,
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
    hash: [u8; 32],
    chaining: [u8; 32],
}

impl Handshake {
    fn new(ephemeral_private: ReusableSecret) -> Self {
        Self {
            ephemeral_private,
            ephemeral_public: [0; 32],
            hash: [0; 32],
            chaining: [0; 32],
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

    pub fn initiate_handshake(&mut self, packet: &mut [u8]) {
        // setup a current in-flight handshake, initialized with just a key so far
        self.handshake = Some(Box::new(Handshake::new(dh_generate())));
        let handshake = self.handshake.as_mut().unwrap();

        // initiator.chaining_key = HASH(CONSTRUCTION)
        hash(&[CONSTRUCTION], &mut handshake.chaining);

        let mut temp = [0; 32];

        // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
        hash(&[&handshake.chaining, IDENTIFIER], &mut temp);
        hash(&[&temp, self.public_key.as_bytes()], &mut handshake.hash);

        // initialize the "simple" fields
        let mut msg = wire::HandshakeInitiation::new(packet);
        // msg.message_type = 1
        *msg.ty_mut() = 0x01;
        // msg.reserved_zero = { 0, 0, 0 }
        *msg.reserved_mut() = [0; 3];
        // msg.sender_index = little_endian(initiator.sender_index)
        *msg.sender_mut() = self.index.to_le_bytes();

        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        *msg.ephemeral_mut() = PublicKey::from(&handshake.ephemeral_private).to_bytes();

        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        hmac(
            &handshake.chaining,
            &[&handshake.ephemeral_public],
            &mut temp,
        );
        // initiator.chaining_key = HMAC(temp, 0x1)
        hmac(&temp, &[&[0x01]], &mut handshake.chaining);

        // agreement = dh(initiator.ephemeral_private, responder.static_public)
        let agreement = dh(&handshake.ephemeral_private, &self.public_key);

        let mut key = [0; 32];

        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        hmac(&handshake.chaining, &[&agreement], &mut temp);
        // initiator.chaining_key = HMAC(temp, 0x1)
        hmac(&temp, &[&[0x01]], &mut handshake.chaining);
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        hmac(&temp, &[&handshake.chaining, &[0x02]], &mut key);

        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let mut tai = tai64::Tai64N::now().to_bytes().to_vec();
        seal_aead(&key, 0, &mut tai, &handshake.hash);
        msg.timestamp_mut().copy_from_slice(&tai);
        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash(&[&handshake.hash, msg.timestamp()], &mut temp);
        handshake.hash = temp;

        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        let mut mac1 = [0; 16];
        hash(&[LABEL_MAC1, self.public_key.as_bytes()], &mut temp);
        mac(
            &temp,
            &[
                &[*msg.ty_()],
                msg.reserved(),
                msg.sender(),
                msg.ephemeral(),
                msg.static_(),
                msg.timestamp(),
            ],
            &mut mac1,
        );
        *msg.mac1_mut() = mac1;

        // if (initiator.last_received_cookie is empty or expired)
        //     msg.mac2 = [zeros]
        // else
        //     msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
        // todo handle cookies
        *msg.mac2_mut() = [0; 16];
    }

    pub fn receive_handshake_initiation(&mut self, packet: &[u8]) -> Option<Handshake> {
        let msg = HandshakeInitiation::new(packet);
    }

    pub fn encode(&mut self, headers: &mut [u8], packet: &mut Vec<u8>) {
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
    pub fn generate(self, peer: &mut Peer, packet: &mut [u8]) {
        peer.initiate_handshake(packet);
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

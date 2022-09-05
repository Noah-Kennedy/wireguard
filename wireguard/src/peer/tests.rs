use super::*;
use rand_core::OsRng;

#[test]
fn smoke_test_handshake_initiation() {
    let mut peer = Peer {
        sessions: Default::default(),
        public_key: PublicKey::from(&ReusableSecret::new(OsRng)),
        handshake: None,
        current: 0,
        index: 7,
    };

    let mut packet = vec![0; 148];

    peer.initiate_handshake(&mut packet);

    let msg = wire::HandshakeInitiation::new(packet);

    assert_eq!(1, *msg.ty_());
    assert_eq!(peer.index, u32::from_le_bytes(*msg.sender()));
    assert_eq!(&[0; 16], msg.mac2());
}

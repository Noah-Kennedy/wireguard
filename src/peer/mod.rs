pub struct Peer {
    // todo
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
    pub fn encode(&self, _peer: &mut Peer, _headers: &mut [u8], _packet: &mut [u8]) {
        todo!()
    }

    pub fn decode(&self, _peer: &mut Peer, _headers: &mut [u8], _packet: &mut [u8]) {
        todo!()
    }
}

impl SendHandshakeInitiationCapability {
    pub fn generate(&self, _peer: &mut Peer, _packet: &mut [u8]) {
        todo!()
    }
}

impl ReceiveHandshakeInitiationCapability {
    pub fn consume(&self, _peer: &mut Peer, _packet: &mut [u8]) {
        todo!()
    }
}

impl ReceiveHandshakeResponseCapability {
    pub fn consume(&self, _peer: &mut Peer, _packet: &mut [u8]) {
        todo!()
    }
}

pub enum Packet<A> {
    HandshakeInitiation(HandshakeInitiation<A>),
    HandshakeResponse(HandshakeResponse<A>),
    CookieReply(CookieReply<A>),
    TransportData(TransportData<A>),
}

pub struct HandshakeInitiation<A> {
    buf: A,
}

pub struct HandshakeResponse<A> {
    buf: A,
}

pub struct CookieReply<A> {
    buf: A,
}

pub struct TransportData<A> {
    buf: A,
}

impl<A> Packet<A>
where
    A: AsRef<[u8]>,
{
    pub fn parse(buf: A) -> Option<Self> {
        let ty = *buf.as_ref().get(0)?;

        let len = buf.as_ref().len();

        match ty {
            1 if len == 116 => Some(Packet::HandshakeInitiation(HandshakeInitiation::new(buf))),
            2 if len == 76 => Some(Packet::HandshakeResponse(HandshakeResponse::new(buf))),
            3 if len == 48 => Some(Packet::CookieReply(CookieReply::new(buf))),
            4 if len >= 16 => Some(Packet::TransportData(TransportData::new(buf))),
            _ => None,
        }
    }
}

impl<A> HandshakeInitiation<A>
where
    A: AsRef<[u8]>,
{
    #[inline]
    pub fn new(buf: A) -> Self {
        Self { buf }
    }

    #[inline]
    pub fn ty_(&self) -> &u8 {
        &self.buf.as_ref()[0]
    }

    #[inline]
    pub fn reserved(&self) -> &[u8; 3] {
        (&self.buf.as_ref()[1..4]).try_into().unwrap()
    }

    #[inline]
    pub fn sender(&self) -> &[u8; 4] {
        (&self.buf.as_ref()[4..8]).try_into().unwrap()
    }

    #[inline]
    pub fn ephemeral(&self) -> &[u8; 32] {
        (&self.buf.as_ref()[8..40]).try_into().unwrap()
    }

    #[inline]
    pub fn static_(&self) -> &[u8; 32] {
        (&self.buf.as_ref()[40..72]).try_into().unwrap()
    }

    #[inline]
    pub fn timestamp(&self) -> &[u8; 12] {
        (&self.buf.as_ref()[72..84]).try_into().unwrap()
    }

    #[inline]
    pub fn mac1(&self) -> &[u8; 16] {
        (&self.buf.as_ref()[84..100]).try_into().unwrap()
    }

    #[inline]
    pub fn mac2(&self) -> &[u8; 16] {
        (&self.buf.as_ref()[100..116]).try_into().unwrap()
    }
}

impl<A> HandshakeInitiation<A>
where
    A: AsMut<[u8]>,
{
    #[inline]
    pub fn ty_mut(&mut self) -> &mut u8 {
        &mut self.buf.as_mut()[0]
    }

    #[inline]
    pub fn reserved_mut(&mut self) -> &mut [u8; 3] {
        (&mut self.buf.as_mut()[1..4]).try_into().unwrap()
    }

    #[inline]
    pub fn sender_mut(&mut self) -> &mut [u8; 4] {
        (&mut self.buf.as_mut()[4..8]).try_into().unwrap()
    }

    #[inline]
    pub fn ephemeral_mut(&mut self) -> &mut [u8; 32] {
        (&mut self.buf.as_mut()[8..40]).try_into().unwrap()
    }

    #[inline]
    pub fn static_mut(&mut self) -> &mut [u8; 32] {
        (&mut self.buf.as_mut()[40..72]).try_into().unwrap()
    }

    #[inline]
    pub fn timestamp_mut(&mut self) -> &mut [u8; 12] {
        (&mut self.buf.as_mut()[72..84]).try_into().unwrap()
    }

    #[inline]
    pub fn mac1_mut(&mut self) -> &mut [u8; 16] {
        (&mut self.buf.as_mut()[84..100]).try_into().unwrap()
    }

    #[inline]
    pub fn mac2_mut(&mut self) -> &mut [u8; 16] {
        (&mut self.buf.as_mut()[100..116]).try_into().unwrap()
    }
}

impl<A> HandshakeResponse<A>
where
    A: AsRef<[u8]>,
{
    #[inline]
    pub fn new(buf: A) -> Self {
        Self { buf }
    }

    #[inline]
    pub fn ty_(&self) -> &u8 {
        &self.buf.as_ref()[0]
    }

    #[inline]
    pub fn reserved(&self) -> &[u8; 3] {
        (&self.buf.as_ref()[1..4]).try_into().unwrap()
    }

    #[inline]
    pub fn sender(&self) -> &[u8; 4] {
        (&self.buf.as_ref()[4..8]).try_into().unwrap()
    }

    #[inline]
    pub fn receiver(&self) -> &[u8; 4] {
        (&self.buf.as_ref()[8..12]).try_into().unwrap()
    }

    #[inline]
    pub fn ephemeral(&self) -> &[u8; 32] {
        (&self.buf.as_ref()[12..44]).try_into().unwrap()
    }

    #[inline]
    pub fn mac1(&self) -> &[u8; 16] {
        (&self.buf.as_ref()[44..60]).try_into().unwrap()
    }

    #[inline]
    pub fn mac2(&self) -> &[u8; 16] {
        (&self.buf.as_ref()[60..76]).try_into().unwrap()
    }
}

impl<A> HandshakeResponse<A>
where
    A: AsMut<[u8; 76]>,
{
    #[inline]
    pub fn ty_mut(&mut self) -> &mut u8 {
        &mut self.buf.as_mut()[0]
    }

    #[inline]
    pub fn reserved_mut(&mut self) -> &mut [u8; 3] {
        (&mut self.buf.as_mut()[1..4]).try_into().unwrap()
    }

    #[inline]
    pub fn sender_mut(&mut self) -> &mut [u8; 4] {
        (&mut self.buf.as_mut()[4..8]).try_into().unwrap()
    }

    #[inline]
    pub fn receiver_mut(&mut self) -> &mut [u8; 4] {
        (&mut self.buf.as_mut()[8..12]).try_into().unwrap()
    }

    #[inline]
    pub fn ephemeral_mut(&mut self) -> &mut [u8; 32] {
        (&mut self.buf.as_mut()[12..44]).try_into().unwrap()
    }

    #[inline]
    pub fn mac1_mut(&mut self) -> &mut [u8; 16] {
        (&mut self.buf.as_mut()[44..60]).try_into().unwrap()
    }

    #[inline]
    pub fn mac2_mut(&mut self) -> &mut [u8; 16] {
        (&mut self.buf.as_mut()[60..76]).try_into().unwrap()
    }
}

impl<A> CookieReply<A>
where
    A: AsRef<[u8]>,
{
    #[inline]
    pub fn new(buf: A) -> Self {
        Self { buf }
    }

    #[inline]
    pub fn ty_(&self) -> &u8 {
        &self.buf.as_ref()[0]
    }

    #[inline]
    pub fn reserved(&self) -> &[u8; 3] {
        (&self.buf.as_ref()[1..4]).try_into().unwrap()
    }

    #[inline]
    pub fn receiver(&self) -> &[u8; 4] {
        (&self.buf.as_ref()[4..8]).try_into().unwrap()
    }

    #[inline]
    pub fn nonce(&self) -> &[u8; 24] {
        (&self.buf.as_ref()[8..32]).try_into().unwrap()
    }

    #[inline]
    pub fn cookie(&self) -> &[u8; 16] {
        (&self.buf.as_ref()[32..48]).try_into().unwrap()
    }
}

impl<A> CookieReply<A>
where
    A: AsMut<[u8]>,
{
    #[inline]
    pub fn ty_mut(&mut self) -> &mut u8 {
        &mut self.buf.as_mut()[0]
    }

    #[inline]
    pub fn reserved_mut(&mut self) -> &mut [u8; 3] {
        (&mut self.buf.as_mut()[1..4]).try_into().unwrap()
    }

    #[inline]
    pub fn receiver_mut(&mut self) -> &mut [u8; 4] {
        (&mut self.buf.as_mut()[4..8]).try_into().unwrap()
    }

    #[inline]
    pub fn nonce_mut(&mut self) -> &mut [u8; 24] {
        (&mut self.buf.as_mut()[8..32]).try_into().unwrap()
    }

    #[inline]
    pub fn cookie_mut(&mut self) -> &mut [u8; 16] {
        (&mut self.buf.as_mut()[32..48]).try_into().unwrap()
    }
}

impl<A> TransportData<A>
where
    A: AsRef<[u8]>,
{
    #[inline]
    pub fn new(buf: A) -> Self {
        Self { buf }
    }

    #[inline]
    pub fn ty_(&self) -> &u8 {
        &self.buf.as_ref()[0]
    }

    #[inline]
    pub fn reserved(&self) -> &[u8; 3] {
        (&self.buf.as_ref()[1..4]).try_into().unwrap()
    }

    #[inline]
    pub fn receiver(&self) -> &[u8; 4] {
        (&self.buf.as_ref()[4..8]).try_into().unwrap()
    }

    #[inline]
    pub fn counter(&self) -> &[u8; 8] {
        (&self.buf.as_ref()[8..16]).try_into().unwrap()
    }

    #[inline]
    pub fn packet(&self) -> &[u8] {
        (&self.buf.as_ref()[16..]).try_into().unwrap()
    }
}

impl<A> TransportData<A>
where
    A: AsMut<[u8]>,
{
    #[inline]
    pub fn ty_mut(&mut self) -> &mut u8 {
        &mut self.buf.as_mut()[0]
    }

    #[inline]
    pub fn reserved_mut(&mut self) -> &mut [u8; 3] {
        (&mut self.buf.as_mut()[1..4]).try_into().unwrap()
    }

    #[inline]
    pub fn receiver_mut(&mut self) -> &mut [u8; 4] {
        (&mut self.buf.as_mut()[4..8]).try_into().unwrap()
    }

    #[inline]
    pub fn counter_mut(&mut self) -> &mut [u8; 8] {
        (&mut self.buf.as_mut()[8..16]).try_into().unwrap()
    }

    #[inline]
    pub fn packet_mut(&mut self) -> &mut [u8] {
        (&mut self.buf.as_mut()[16..]).try_into().unwrap()
    }
}

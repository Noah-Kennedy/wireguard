use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use slab::Slab;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

pub struct CryptokeyRouter<P> {
    peers: Slab<CryptokeyRoutingPeer<P>>,
    keymap: HashMap<[u8; 32], usize>,
    ip_table: IpNetworkTable<usize>,
}

pub struct CryptokeyRoutingPeer<P> {
    peer: P,
    endpoint: Option<SocketAddr>,
    ip_net: IpNetwork,
}

impl<P> CryptokeyRouter<P> {
    pub fn new() -> Self {
        let peers = Slab::new();
        let keymap = HashMap::new();
        let ip_table = IpNetworkTable::new();

        Self {
            peers,
            keymap,
            ip_table,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let peers = Slab::with_capacity(capacity);
        let keymap = HashMap::with_capacity(capacity);
        let ip_table = IpNetworkTable::with_capacity(capacity, capacity);

        Self {
            peers,
            keymap,
            ip_table,
        }
    }

    pub fn get_by_pubkey(&self, key: &[u8; 32]) -> Option<&CryptokeyRoutingPeer<P>> {
        let slab_key = self.keymap.get(key)?;
        self.peers.get(*slab_key)
    }

    pub fn get_by_pubkey_mut(&mut self, key: &[u8; 32]) -> Option<&mut CryptokeyRoutingPeer<P>> {
        let slab_key = self.keymap.get(key)?;
        self.peers.get_mut(*slab_key)
    }

    pub fn get_by_ip(&self, key: IpAddr) -> Option<&CryptokeyRoutingPeer<P>> {
        let (_, slab_key) = self.ip_table.longest_match(key)?;
        self.peers.get(*slab_key)
    }

    pub fn get_by_ip_mut(&mut self, key: IpAddr) -> Option<&mut CryptokeyRoutingPeer<P>> {
        let (_, slab_key) = self.ip_table.longest_match(key)?;
        self.peers.get_mut(*slab_key)
    }

    pub fn add_peer(
        &mut self,
        peer: P,
        key: [u8; 32],
        net: IpNetwork,
        endpoint: Option<SocketAddr>,
    ) -> Option<CryptokeyRoutingPeer<P>> {
        let slab_key = self.peers.insert(CryptokeyRoutingPeer {
            peer,
            endpoint,
            ip_net: net,
        });

        let old_key = self.keymap.insert(key, slab_key);
        let old_key2 = self.ip_table.insert(net, slab_key);

        debug_assert_eq!(old_key, old_key2);

        self.peers.try_remove(old_key?)
    }

    pub fn remove_peer(&mut self, key: &[u8; 32]) -> Option<CryptokeyRoutingPeer<P>> {
        let slab_key = self.keymap.remove(key)?;

        let peer = self.peers.try_remove(slab_key)?;
        let slab_key_2 = self.ip_table.remove(peer.ip_net);

        debug_assert_eq!(slab_key, slab_key_2.unwrap());

        Some(peer)
    }
}

impl<P> CryptokeyRoutingPeer<P> {
    pub fn peer(&self) -> &P {
        &self.peer
    }

    pub fn peer_mut(&mut self) -> &mut P {
        &mut self.peer
    }

    pub fn endpoint(&self) -> Option<&SocketAddr> {
        self.endpoint.as_ref()
    }

    pub fn set_endpoint(&mut self, addr: SocketAddr) {
        debug_assert!(self.ip_net.contains(addr.ip()));
        self.endpoint = Some(addr);
    }

    pub fn clear_endpoint(&mut self) {
        self.endpoint = None;
    }
}

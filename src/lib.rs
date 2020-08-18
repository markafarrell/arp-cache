use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::IpAddr;

use std::{thread, time};

use pcap;
use pnet::datalink::{
    self,
    MacAddr
};
use pnet::packet::{
    MutablePacket,
    Packet
};
use pnet::packet::ethernet::{
    EtherTypes,
    EthernetPacket,
    MutableEthernetPacket
};
use pnet::packet::arp::{
    MutableArpPacket,
    ArpHardwareTypes,
    ArpOperations,
    ArpPacket
};

pub struct ArpCache {
    arp_table: HashMap<Ipv4Addr,datalink::MacAddr>,
    interface: datalink::NetworkInterface,
    gateway: Ipv4Addr
}

impl ArpCache {
    pub fn new(interface_name: &str, gateway: Ipv4Addr) -> Option<Self> {
        // Initialise a new ArpCache for interface_name. Return None if the interface doesn't exist
        let interfaces = datalink::interfaces();

        if let Some(interface) = interfaces.into_iter().find(|iface| iface.name == interface_name) {
            Some(
                ArpCache {
                    arp_table: HashMap::new(),
                    interface: interface,
                    gateway: gateway,
                }
            )
        }
        else {
            None
        }
    }

    pub fn get_mac(&mut self, target_ip: Ipv4Addr) -> Option<datalink::MacAddr> {
        // First check if the mapping is in the arp_table. If not request it over ARP. 
        // If there is no response then return None

        // Check if the requested ip address is in our subnet

        let mut target_ip = target_ip;

        if !self.interface
            .ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .unwrap()
            .contains(IpAddr::V4(target_ip)) {
                // if the target IP is NOT in our subnet then get the mac address of the gateway
                target_ip = self.gateway;
            }

        match self.arp_table.get(&target_ip) {
            Some(&mac_address) => Some(mac_address),
            None => {
                match self.get_mac_through_arp(target_ip) {
                    Some(mac_address) => {
                        self.arp_table.insert(target_ip, mac_address);
                        Some(mac_address)
                    },
                    None => None
                }
            }
        }
    }

    fn get_mac_through_arp(&self, target_ip: Ipv4Addr) -> Option<datalink::MacAddr> {
        // Blatently copied from the pnet examples https://github.com/libpnet/libpnet/blob/master/examples/arp_packet.rs
        let source_ip = self.interface
            .ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .map(|ip| match ip.ip() {
                IpAddr::V4(ip) => ip,
                _ => unreachable!(),
            })
            .unwrap();

        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    
        ethernet_packet.set_destination(datalink::MacAddr::broadcast());
        ethernet_packet.set_source(self.interface.mac.unwrap());
        ethernet_packet.set_ethertype(EtherTypes::Arp);
    
        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(self.interface.mac.unwrap());
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);
    
        ethernet_packet.set_payload(arp_packet.packet_mut());
        
        let filter = format!("(arp[6:2] = 2) and dst host {} and ether dst {}", source_ip, self.interface.mac.unwrap());

        for i in 0..3 {
            // Try the request 3 times. If we don't get a response bail out

            let (mut sender, _) = match datalink::channel(&self.interface, Default::default()) {
                Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("Unknown channel type"),
                Err(e) => panic!("Error happened {}", e),
            };

            let pcap_device = if let Ok(devices) = pcap::Device::list() {
                if let Some(device) = devices.into_iter().find(|d| d.name == self.interface.name) {
                    device
                }
                else {
                    panic!("Could not capture from device {}", self.interface.name);
                }
            }
            else {
                panic!("Could not get list of capture devices");
            };

            let mut cap = pcap::Capture::from_device(pcap_device).unwrap().timeout(0).open().unwrap().setnonblock().unwrap();
            cap.filter(&filter).unwrap();
            
            sender
            .send_to(ethernet_packet.packet(), None)
            .unwrap()
            .unwrap();

            // Wait for 100 ms more each try
            thread::sleep(time::Duration::from_millis(200*(i+1)));

            if let Ok(packet) = cap.next() {
                
                if let Some(e_packet) = EthernetPacket::new(packet.data) {
                    let ethertype = e_packet.get_ethertype();

                    if ethertype ==  EtherTypes::Arp {
                        let arp_packet = ArpPacket::new(e_packet.payload()).unwrap();
                        
                        if arp_packet.get_operation() == ArpOperations::Reply {
                            // It is a reply

                            if arp_packet.get_sender_proto_addr() == target_ip {
                                // It a reply from the IP we want
                                return Some(arp_packet.get_sender_hw_addr());
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        // Test with valid device

        let arp_cache = ArpCache::new("eth0", Ipv4Addr::new(172, 28, 176, 1));

        assert!(arp_cache.is_some());

        let arp_cache = ArpCache::new("eth1", Ipv4Addr::new(172, 28, 176, 1));

        assert!(arp_cache.is_none());
    }

    #[test]
    fn test_get_valid_ip() {
        if let Some(mut arp_cache) = ArpCache::new("eth0", Ipv4Addr::new(172, 28, 176, 1)) {
            // Address should not be in the hashmap
            assert!(arp_cache.arp_table.contains_key(&Ipv4Addr::new(172, 28, 176, 1)) == false);

            let mac = arp_cache.get_mac(Ipv4Addr::new(172, 28, 176, 1));

            if let Some(_mac) = mac {
                // Check the entry is in the hashmap
                assert!(arp_cache.arp_table.contains_key(&Ipv4Addr::new(172, 28, 176, 1)));
            }
            else
            {
                assert!(false);
            }
        }
        else {
            assert!(false);
        }
    }

    #[test]
    fn test_get_mac_outside_subnet() {
        if let Some(mut arp_cache) = ArpCache::new("eth0", Ipv4Addr::new(172, 28, 176, 1)) {

            let mac = arp_cache.get_mac(Ipv4Addr::new(8, 8, 8, 8));
            let mac_gateway = arp_cache.get_mac(Ipv4Addr::new(172, 28, 176, 1));

            assert!(mac.is_some());

            assert!(mac_gateway.is_some());

            assert_eq!(mac.unwrap(), mac_gateway.unwrap());
        }
        else {
            assert!(false);
        }
    }

    #[test]
    fn test_get_invalid_ip() {
        if let Some(mut arp_cache) = ArpCache::new("eth0", Ipv4Addr::new(172, 28, 176, 1)) {
            // Address should not be in the hashmap
            assert!(arp_cache.arp_table.contains_key(&Ipv4Addr::new(172, 28, 176, 2)) == false);

            let mac = arp_cache.get_mac(Ipv4Addr::new(172, 28, 176, 2));

            if let Some(_) = mac {
                assert!(false);
            }
            else
            {
                assert!(true);
            }
        }
        else {
            assert!(false);
        }
    }
}

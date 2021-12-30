#![no_std]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PacketLog {
    pub ipv4_header: Ipv4Header,
    pub udp_header: UdpHeader,
    pub action: u32,
}

pub struct EthernetHeader {
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Ipv4Header {
    // version, IHL
    // pub tos: u8,
    pub total_length: u16,
    pub id: u16,
    pub ttl: u8,
    // pub flagment_offset: u16,
    pub protocol: u8,
    pub checksum: u16,
    pub src_address: u32,
    pub dst_address: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UdpHeader {
    pub source: u16,
    pub dest: u16,
    pub length: u16,
    pub checksum: u16,
}


#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Ipv4Header {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for UdpHeader {}

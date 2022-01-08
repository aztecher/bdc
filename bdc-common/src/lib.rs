#![no_std]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PacketLog {
    // pub ipv4_header: Ipv4Header,
    // pub udp_header: UdpHeader,
    // pub dns_header: DnsHeader,
    // pub dns_flags: DnsFlags,
    // pub action: u32,
    // pub question: Question,
    pub ipv4: u32,
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

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DnsHeader {
    pub transaction_id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answer_rrs: u16,
    pub authority_rrs: u16,
    pub additional_rrs: u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DnsFlags {
    pub qr: QR,
    pub opcode: OpCode,
    pub aa: AA,
    pub tc: TC,
    pub rd: RD,
    pub ra: RA,
    pub z: Z,
    pub ad: AD,
    pub cd: CD,
    pub rcode: RCode
}

impl From<u16> for DnsFlags {
    fn from(item: u16) -> Self {
        DnsFlags {
            qr: QR::from(item),
            opcode: OpCode::from(item),
            aa: AA::from(item),
            tc: TC::from(item),
            rd: RD::from(item),
            ra: RA::from(item),
            z: Z::from(item),
            ad: AD::from(item),
            cd: CD::from(item),
            rcode: RCode::from(item),
        }
    }
}

const MASK_1BIT: u16 = 1_u16;
const MASK_4BIT: u16 = 15_u16;

fn _flag_parse(flag: u16, shift: u16, mask: u16) -> u16 {
    (flag >> shift) & mask
}

fn _flag_construct(flag: u16, shift: u16) -> u16 {
    flag << shift
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct QR {
    decimal: u16,
}

impl From<u16> for QR {
    fn from(item: u16) -> Self {
        QR { decimal: _flag_parse(item, 15, MASK_1BIT) }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OpCode {
    decimal: u16,
}

impl From<u16> for OpCode {
    fn from(item: u16) -> Self {
        OpCode { decimal: _flag_parse(item, 11, MASK_4BIT) }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AA {
    decimal: u16,
}

impl From<u16> for AA {
    fn from(item: u16) -> Self {
        AA { decimal: _flag_parse(item, 10, MASK_1BIT) }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TC {
    decimal: u16,
}

impl From<u16> for TC {
    fn from(item: u16) -> Self {
        TC { decimal: _flag_parse(item, 9, MASK_1BIT) }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RD {
    decimal: u16,
}

impl From<u16> for RD {
    fn from(item: u16) -> Self {
        RD { decimal: _flag_parse(item, 8, MASK_1BIT) }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RA {
    decimal: u16,
}

impl From<u16> for RA {
    fn from(item: u16) -> Self {
        RA { decimal: _flag_parse(item, 7, MASK_1BIT) }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Z {
    decimal: u16,
}

impl From<u16> for Z {
    fn from(item: u16) -> Self {
        Z { decimal: _flag_parse(item, 6, MASK_1BIT) }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AD {
    decimal: u16,
}

impl From<u16> for AD {
    fn from(item: u16) -> Self {
        AD { decimal: _flag_parse(item, 5, MASK_1BIT) }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CD {
    decimal: u16,
}

impl From<u16> for CD {
    fn from(item: u16) -> Self {
        CD { decimal: _flag_parse(item, 4, MASK_1BIT) }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RCode {
    decimal: u16,
}

impl From<u16> for RCode {
    fn from(item: u16) -> Self {
        RCode { decimal: _flag_parse(item, 0, MASK_4BIT) }
    }
}

pub const MAX_DNS_NAME_LENGTH: usize = 40;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Question {
    pub data: [u8; MAX_DNS_NAME_LENGTH],
}

impl Default for Question {
    fn default() -> Self {
        Question {
            data: [0; MAX_DNS_NAME_LENGTH],
        }
    }
}


#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Ipv4Header {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for UdpHeader {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsHeader {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsFlags {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for QR {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for OpCode {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AA {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TC {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RD {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RA {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Z {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AD {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CD {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RCode {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Question {}

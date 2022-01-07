#![no_std]
#![no_main]

use core::mem;
use memoffset::offset_of;
use unroll::unroll_for_loops;
use usize_cast::IntoUsize;
use aya_log_ebpf::info;
mod bindings;
use bindings::{
    __u16,
    ethhdr,
    iphdr,
    udphdr,
};
use aya_bpf::{
    macros::{
        classifier,
        map,
        xdp,
    },
    programs::{
        SkBuffContext,
        XdpContext,
    },
    maps::PerfEventArray,
    maps::HashMap,
    bindings::xdp_action,
};

pub use bdc_common::{
    PacketLog,
    Ipv4Header,
    UdpHeader,
    DnsHeader,
    DnsFlags,
    MAX_DNS_NAME_LENGTH,
    Question,
};

const ETH_P_IP: u16      = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize  = mem::size_of::<iphdr>();
const UDP_HDR_LEN: usize = mem::size_of::<udphdr>();
const DNS_HDR_LEN: usize = mem::size_of::<dnshdr>();
const UDP_PROTOCOL: u8   = 17;
const OFFSET_16BIT: usize = mem::size_of::<u16>();
const OFFSET_8BIT: usize = mem::size_of::<u8>();
const DNS_PORT: u16      = 53;


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct dnshdr {
    pub transaction_id: __u16,
    pub flags: __u16,
    pub questions: __u16,
    pub answer_rrs: __u16,
    pub authority_rrs: __u16,
    pub additional_rrs: __u16,
}

#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::<u32,u32>::with_max_entries(1024, 0);

#[map(name = "BLOCKEVENTS")]
static mut BLOCKEVENTS: PerfEventArray<PacketLog> = PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[classifier(name="bdc")]
pub fn bdc(ctx: SkBuffContext) -> i32 {
    match unsafe { try_bdc(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_bdc(_ctx: SkBuffContext) -> Result<i32, i32> {
    Ok(0)
}


#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

fn block_ip(address: &u32) -> bool {
    unsafe { BLOCKLIST.get(address).is_some() }
}

fn is_udp(protocol: &u8) -> bool {
    if *protocol == UDP_PROTOCOL {
        return true
    }
    false
}

fn is_dns_port(port: &u16) -> bool {
    if *port == DNS_PORT {
        return true
    }
    false
}

#[unroll_for_loops]
fn parse_query(ctx: &XdpContext) -> Result<[u8; MAX_DNS_NAME_LENGTH], ()>{
    let mut r: [u8; MAX_DNS_NAME_LENGTH] = [0; MAX_DNS_NAME_LENGTH];
    let mut label_loc: u8 = 0;
    let mut cursor = 0;
    let question_offset = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + DNS_HDR_LEN;
    for index in 0..40 {
        // MEMO: MAX_DNS_NAME_LENGTH(=40) caused error used in this code?
        // > invalid access to packet, off=54 size=1, R3(id=0,off=54,r=53)
        // > 3 offset is outside of the packet
        let offset = index * OFFSET_8BIT;
        let t_offset = question_offset + offset;
        let data: u8 = u8::from_be( unsafe { *ptr_at(&ctx, t_offset)? } );
        if label_loc == offset as u8 {
            // check if the location is root label
            if data == 0 {
                return Ok(r)
            }
            // calculate next label location
            if label_loc + data + 1 < MAX_DNS_NAME_LENGTH as u8 {
                label_loc = label_loc + data + 1;
            } else {
                return Err(())
            }
        } else {
            r[cursor] = data;
            cursor += 1;
        }
    }
    Ok(r)
}

#[xdp]
pub fn xdp_rx_filter(ctx: XdpContext) -> u32 {
    match try_xdp_rx_filter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}


fn try_xdp_rx_filter(ctx: XdpContext) -> Result<u32, ()>{
    let h_proto = u16::from_be(
        unsafe {
            *ptr_at(&ctx, offset_of!(ethhdr, h_proto))?
        }
    );
    if h_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip = to_ipv4_hdr(&ctx)?;
    if !block_ip(&ip.src_address) {
        return Ok(xdp_action::XDP_PASS)
    }
    if !is_udp(&ip.protocol) {
        return Ok(xdp_action::XDP_PASS)
    }
    let udp = to_udp_hdr(&ctx)?;
    if !is_dns_port(&udp.source) {
        return Ok(xdp_action::XDP_PASS)
    }
    // let dns = to_dns_hdr(&ctx)?;
    // let question = to_question(&ctx)?;
    let parse_result = match parse_query(&ctx) {
        Ok(r) => r,
        Err(_) => [0; MAX_DNS_NAME_LENGTH],
    };
    let log_entry = PacketLog {
        // ipv4_header: ip,
        // udp_header: udp,
        // dns_header: dns,
        // action: xdp_action::XDP_DROP,
        // question,
        question: Question {
            data: parse_result,
        },
    };
    unsafe {
        BLOCKEVENTS.output(&ctx, &log_entry, 0);
    }
    Ok(xdp_action::XDP_DROP)
}


fn to_ipv4_hdr(ctx: &XdpContext) -> Result<Ipv4Header, ()> {
    // MEMO: memoffset::offset_of is very useful but if you don't specify packed in repr(C, packed)
    // then memory alignment is not suitable for this function and access error will be occurred.
    // so, if you want to full struct of C structure, then you migit better to consider another
    // implimemtation.
    let total_length = u16::from_be(
        unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, tot_len))? }
    );
    let id = u16::from_be(
        unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, id))? }
    );
    let ttl = u8::from_be(
        unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, ttl))? }
    );
    let protocol = u8::from_be(
        unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? }
    );
    let checksum = u16::from_be(
        unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, check))? }
    );
    let src_address = u32::from_be(
        unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? }
    );
    let dst_address = u32::from_be(
        unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))? }
    );
    Ok(
        Ipv4Header {
            total_length,
            id,
            ttl,
            protocol,
            checksum,
            src_address,
            dst_address,
        }
    )
}

fn to_udp_hdr(ctx: &XdpContext)-> Result<UdpHeader, ()> {
    let source = u16::from_be(
        unsafe {
            *ptr_at(
                &ctx,
                ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, source)
            )?
        }
    );
    let dest = u16::from_be(
        unsafe {
            *ptr_at(
                &ctx,
                ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, dest)
            )?
        }
    );
    let length = u16::from_be(
        unsafe {
            *ptr_at(
                &ctx,
                ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, len)
            )?
        }
    );
    let checksum = u16::from_be(
        unsafe {
            *ptr_at(
                &ctx,
                ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, check)
            )?
        }
    );
    Ok(
        UdpHeader {
            source,
            dest,
            length,
            checksum,
        }
    )
}

fn to_dns_hdr(ctx: &XdpContext) -> Result<DnsHeader, ()> {
    let offset_to_dns = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    let transaction_id = u16::from_be(
        unsafe {
            *ptr_at(
                &ctx,
                offset_to_dns + offset_of!(dnshdr, transaction_id)
            )?
        }
    );
    let flags = u16::from_be(
        unsafe {
            *ptr_at(
                &ctx,
                offset_to_dns + offset_of!(dnshdr, flags)
            )?
        }
    );
    let questions = u16::from_be(
        unsafe {
            *ptr_at(
                &ctx,
                offset_to_dns + offset_of!(dnshdr, questions)
            )?
        }
    );
    let answer_rrs = u16::from_be(
        unsafe {
            *ptr_at(
                &ctx,
                offset_to_dns + offset_of!(dnshdr, answer_rrs)
            )?
        }
    );
    let authority_rrs = u16::from_be(
        unsafe {
            *ptr_at(
                &ctx,
                offset_to_dns + offset_of!(dnshdr, authority_rrs)
            )?
        }
    );
    let additional_rrs = u16::from_be(
        unsafe {
            *ptr_at(
                &ctx,
                offset_to_dns + offset_of!(dnshdr, additional_rrs)
            )?
        }
    );
    Ok(
        DnsHeader {
            transaction_id,
            flags,
            questions,
            answer_rrs,
            authority_rrs,
            additional_rrs,
        }
    )
}

// fn to_question(ctx: &XdpContext) -> Result<Question, ()> {
//     let offset_to_question = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + DNS_HDR_LEN;
//     let data: [u32; 16] = unsafe { *ptr_at(&ctx, offset_to_question)? };
//     Ok(
//         Question {
//             parse_result: 0,
//             raw_data: [0; MAX_DNS_NAME_LENGTH],
//             data,
//             label_lens: [0; 16],
//         }
//     )
//
// }

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}


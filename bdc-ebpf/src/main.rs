#![no_std]
#![no_main]
#![feature(never_type)]

use core::mem;
use memoffset::offset_of;
use unroll::unroll_for_loops;
use usize_cast::IntoUsize;
use aya_log_ebpf::info;
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;
use bindings::{
    __u16,
    ethhdr,
    iphdr,
    udphdr,
};
use aya_bpf::{
    BpfContext,
    macros::{
        classifier,
        map,
        xdp,
    },
    programs::{
        SkBuffContext,
        XdpContext,
    },
    maps::{PerfEventArray, HashMap, ProgramArray},
    bindings::xdp_action,
    helpers::gen::bpf_xdp_adjust_head,
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

#[map(name = "DNSCACHE")]
static mut DNSCACHE: HashMap<Question, u32> = HashMap::<Question, u32>::with_max_entries(1024, 0);

#[map(name = "JUMP_TABLE")]
static mut JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(10, 0);

#[map(name = "TAIL_CALL_EVENTS")]
static mut TAIL_CALL_EVENTS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(10, 0);

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

fn cache_search(fqdn: &Question) -> Option<&u32> {
    unsafe { DNSCACHE.get(fqdn) }
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
    for index in 0..60 {
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

#[xdp(name="rx_filter")]
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
    if !is_dns_port(&udp.dest) {
        return Ok(xdp_action::XDP_PASS)
    }
    // JUMP to rx_parse_question
    unsafe {
        if let Err(_) = JUMP_TABLE.tail_call(&ctx, 0) {
            return Ok(xdp_action::XDP_PASS)
        }
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

#[xdp(name="rx_parse_question")]
pub fn rx_parse_question(ctx: XdpContext) -> u32 {
    info!(&ctx, "[tail_call] rx_parse_question");
    let parse_result = parse_query(&ctx).unwrap_or([0; MAX_DNS_NAME_LENGTH]);
    let question = Question { data: parse_result };
    let ipv4 = *cache_search(&question).unwrap_or(&0);
    let log_entry = PacketLog { ipv4 };
    unsafe {
        BLOCKEVENTS.output(&ctx, &log_entry, 0);
        // Jump to prepare_packet
        if let Err(_) = JUMP_TABLE.tail_call(&ctx, 1) {
            return xdp_action::XDP_PASS
        }
    }
    xdp_action::XDP_DROP
}

// pub unsafe fn xdp_adjust_head(ctx: &XdpContext, index: i32) -> Result<!, i64> {
//     let res = bpf_xdp_adjust_head(ctx.ctx, index);
//     if res != 0 {
//         Err(res)
//     } else {
//         core::hint::unreachable_unchecked()
//     }
// }

#[xdp(name="prepare_packet")]
pub fn prepare_packet(ctx: XdpContext) -> u32 {
    info!(&ctx, "[tail_call] prepare_packet");
    let adjust_head_len: i32 = 128;
    unsafe {
        // if let Err(_) = xdp_adjust_head(&ctx, -adjust_head_len) {
        //     return xdp_action::XDP_PASS
        // }
        // if let Err(_) = xdp_adjust_head(&ctx, adjust_head_len) {
        //     return xdp_action::XDP_PASS
        // }
        // Jump to write_reply
        if let Err(_) = JUMP_TABLE.tail_call(&ctx, 2) {
            return xdp_action::XDP_PASS
        }
    }
    xdp_action::XDP_DROP
}

#[xdp(name="write_reply")]
pub fn write_reply(ctx: XdpContext) -> u32 {
    info!(&ctx, "[tail_call] write_reply");
    xdp_action::XDP_DROP
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}


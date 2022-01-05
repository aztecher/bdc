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

const MAX_DNS_NAME_LENGTH: u16 = 256;


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

#[inline(never)]
#[unroll_for_loops]
fn parse_dns_query(
    question: &Question,
    res: &mut [u32; 16],
    label_lens: &mut [u8; 16],
    raw_data: &mut [u8; 32],
    ) -> Result<(), i32>
{
    let mut label_len: u8 = 0;
    let mut res_cursor: usize = 0;
    let mut chunk: [u8; 4] = [0; 4];
    let mut chunk_cursor: usize  = 0;
    let mut label_lens_cursor: usize = 0;
    let mut raw_data_cursor: usize = 0;
    for index_u32 in 0..16 {
        let data: u32 = question.data[index_u32];
        let data_u8: [u8; 4] = data.to_be_bytes();
        for index_u8 in 0..4 {
            let index_u8_rev = 3 - index_u8;
            let d = data_u8[index_u8_rev];
            let subcursor = index_u32 * 4 + index_u8;
            // TODO: Bellow code cause eBPF verifyer error of 'no space left on device'
            // Will checkout how to figure out the methods of expand eBPF buffer size.
            //
            // BPF_PROG_LOAD systemcall's bpf buffer size is setted here.
            // https://github.com/aya-rs/aya/blob/faa36763f78d3190492508ce9ed40d98eca81750/aya/src/sys/bpf.rs#L85-L90
            //
            // /home/mmichish/.cargo/registry/src/github.com-1ecc6299db9ec823/aya-0.10.6/src/programs/mod.rs
            // grow -> MAX_LOG_BUF_SIZE=(std::u32::MAX >> 8) as usize = 16777215
            let d_some = if d == 0 { Some(0) }
            else if d == 1 { Some(1) }
            else if d == 2 { Some(2) }
            else if d == 3 { Some(3) }
            else if d == 4 { Some(4) }
            else if d == 5 { Some(5) }
            else if d == 6 { Some(6) }
            else if d == 7 { Some(7) }
            else if d == 8 { Some(8) }
            else if d == 9 { Some(9) }
            else if d == 10 { Some(10) }
            else if d == 11 { Some(11) }
            else if d == 12 { Some(12) }
            else { None };
            match d_some {
                Some(v) => {
                    if subcursor as u8 == label_len {
                        if v == 0 {
                            return Ok(())
                        }
                        label_len += v + 1;
                        label_lens[label_lens_cursor] = label_len;
                        label_lens_cursor += 1;
                    } else {
                        if chunk_cursor == 4 {
                            res[res_cursor] = u32::from_be_bytes(chunk);
                            res_cursor += 1;
                            chunk = [0; 4];
                            chunk_cursor = 0;
                        } else {
                            chunk[chunk_cursor] = v;
                            chunk_cursor += 1;
                        }
                    }
                },
                None => {
                    raw_data[raw_data_cursor] = 120;
                }
            }
        }
    }
    Ok(())
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
    let dns = to_dns_hdr(&ctx)?;
    let question = to_question(&ctx)?;
    let mut res = [0; 16];
    let mut raw_data = [0; 32];
    let mut label_lens = [0; 16];
    let parse_result = match parse_dns_query(
        &question,
        &mut res,
        &mut label_lens,
        &mut raw_data,
    ) {
        Ok(()) => 1,
        Err(e) => e,
    };
    let log_entry = PacketLog {
        // ipv4_header: ip,
        // udp_header: udp,
        // dns_header: dns,
        // action: xdp_action::XDP_DROP,
        // question,
        question: Question {
            parse_result,
            raw_data,
            label_lens,
            data: res,
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

fn to_question(ctx: &XdpContext) -> Result<Question, ()> {
    let offset_to_question = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + DNS_HDR_LEN;
    let data: [u32; 16] = unsafe { *ptr_at(&ctx, offset_to_question)? };
    Ok(
        Question {
            parse_result: 0,
            raw_data: [0; 32],
            data,
            label_lens: [0; 16],
        }
    )

}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}


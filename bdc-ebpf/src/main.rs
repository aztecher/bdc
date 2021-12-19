#![no_std]
#![no_main]

use core::mem;
use memoffset::offset_of;
mod bindings;
use bindings::{ethhdr, iphdr};

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

// pub use bdc_common::PacketLog;

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::<u32,u32>::with_max_entries(1023, 0);

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

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}


fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()>{
    let h_proto = u16::from_be(
        unsafe {
            *ptr_at(&ctx, offset_of!(ethhdr, h_proto))?
        }
    );
    if h_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    let source = u32::from_be(
        unsafe {
            *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))?
        }
    );
    let action = if block_ip(source) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };

    Ok(action)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

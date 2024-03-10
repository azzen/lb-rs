#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::{xdp, map}, programs::XdpContext, maps::HashMap};
use aya_log_ebpf::info;

mod bindings;
use bindings::{ethhdr, iphdr, udphdr};
use load_balancer_common::BackendPorts;
use core::mem;

const IPPROTO_UDP: u8 = 0x0011;
const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();

// Map to associate inbound destination port with backend ports
#[map(name="BACKEND_PORTS")]
static mut BACKEND_PORTS: HashMap<u16, BackendPorts> = HashMap::<u16, BackendPorts>::with_max_entries(10, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    
    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}

#[xdp]
pub fn load_balancer(ctx: XdpContext) -> u32 {
    match try_load_balancer(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_load_balancer(ctx: XdpContext) -> Result<u32, u32> {
    //info!(&ctx, "received a packet");

    // check if it is an IP packet
    let eth = ptr_at::<ethhdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { u16::from_be((*eth).h_proto) } != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    // check if it is UDP
    let ip = ptr_at::<iphdr>(&ctx, ETH_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { (*ip).protocol } != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    info!(&ctx, "Received a UDP Packet");

    let udp = ptr_at_mut::<udphdr>(&ctx, ETH_HDR_LEN + IP_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    let dport = unsafe { u16::from_be((*udp).dest) };

    // check if we can redirect the packet if not pass
    let backends = match unsafe { BACKEND_PORTS.get(&dport) } {
        Some(backends) => {
            info!(&ctx, "FOUND backends for port");
            backends
        }
        None => {
            info!(&ctx, "NO backends found for this port");
            return Ok(xdp_action::XDP_PASS);
        }
    };

    if backends.index > backends.ports.len() - 1 {
        return Ok(xdp_action::XDP_ABORTED);
    }

    // modify destination port
    let new_dport = backends.ports[backends.index];
    unsafe { (*udp).dest = u16::from_be(new_dport) };

    info!(&ctx, "Redirected port {} to {}", dport, new_dport);

    // round-robin strategy
    let mut new_backends = BackendPorts {
        ports: backends.ports,
        index: backends.index + 1,
    };

    if new_backends.index > new_backends.ports.len() - 1 || new_backends.ports[new_backends.index] == 0 {
        new_backends.index = 0;
    }

    match unsafe { BACKEND_PORTS.insert(&dport, &new_backends, 0) } {
        Ok(_) => {
            info!(&ctx, "index updated for port {}", dport);
            Ok(xdp_action::XDP_PASS)
        }
        Err(err) => {
            info!(&ctx, "Error inserting index update: {}", err);
            Ok(xdp_action::XDP_ABORTED)
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

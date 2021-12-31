use aya::{
    programs::{
        tc,
        SchedClassifier,
        TcAttachType,
        Xdp,
        XdpFlags,
    },
    maps::{
        perf::AsyncPerfEventArray,
        HashMap,
        MapRefMut,
    },
    include_bytes_aligned,
    Bpf,
    util::online_cpus,
};
use std::{
    convert::{TryFrom, TryInto},
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    thread,
    time::Duration,
    net::{
        self,
        Ipv4Addr,
    },
};
use std::io::{BufReader, BufRead};
use std::fs::File;
use structopt::StructOpt;
use tokio::{signal, task};
use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use bdc_common::{PacketLog, Ipv4Header};

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long, default_value = "eth0")]
    iface: String,
    #[structopt(short, long, default_value = "xdp")]
    bpftype: String,
}

const ENV_BLOCK_LIST: &str = "ENV_BLOCK_LIST";

fn load_block_list(block_list: &mut HashMap<MapRefMut, u32, u32>) -> Result<()>{
    let block_file = std::env::var(ENV_BLOCK_LIST)
        .context(format!("Environmental variable {} not found or contains invalid character", ENV_BLOCK_LIST))?;
    let f = File::open(&block_file)
        .context(format!("Cannot open file {}", block_file))?;
    let reader = BufReader::new(f);
    for host in reader.lines() {
        let parsed: Vec<u8> = host.unwrap().split(".")
            .map(|s| s.parse().unwrap())
            .collect();
        if parsed.len() != 4 {
            return Err(
                anyhow!(format!("IP list parse error, unexpected length of parsed result"))
            )
        }
        let ipv4: u32 = Ipv4Addr::new(
            parsed[0],
            parsed[1],
            parsed[2],
            parsed[3]).try_into()?;
        block_list.insert(ipv4, 0, 0)?;
    };
    Ok(())
}

#[tokio::main]
// fn try_main() -> Result<(), anyhow::Error> {
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();
    // This will include youe eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/bdc"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/bdc"
    ))?;

    if opt.bpftype == "xdp" {
        let probe: &mut Xdp = bpf.program_mut("xdp").unwrap().try_into()?;
        probe.load()?;
        probe.attach(&opt.iface, XdpFlags::default())?;

        let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST")?)?;
        load_block_list(&mut blocklist)?;

        let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("BLOCKEVENTS")?)?;

        for cpu_id in online_cpus()? {
            let mut buf = perf_array.open(cpu_id, None)?;
            task::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();

                loop {
                    let events = buf.read_events(&mut buffers).await.unwrap();
                    for i in 0..events.read {
                        let buf = &mut buffers[i];
                        let ptr = buf.as_ptr() as *const PacketLog;
                        let data = unsafe { ptr.read_unaligned() };
                        let src_addr = net::Ipv4Addr::from(data.ipv4_header.src_address);
                        let dst_addr = net::Ipv4Addr::from(data.ipv4_header.dst_address);
                        println!("LOG(IP HDR): BLOCKED SRC ADDR {}, DST ADDR {}, ACTION {}, TTL {}, PROTOCOL {}",
                            src_addr, dst_addr, data.action, data.ipv4_header.ttl,
                            data.ipv4_header.protocol);
                        println!("LOG(UDP HDR): BLOCKED SRC_PORT {}, DST PORT {}, SEG_LEN {}",
                            data.udp_header.source,
                            data.udp_header.dest,
                            data.udp_header.length);
                        println!("LOG(DNS_HDR): BLOCEKD TRANSACTION ID {:#04x}, Question: {}, ANS RRs: {}, Auth RRs {}, Addi RRs {}", 
                            data.dns_header.transaction_id,
                            data.dns_header.questions,
                            data.dns_header.answer_rrs,
                            data.dns_header.authority_rrs,
                            data.dns_header.additional_rrs);
                    }
                }
            });
        }
        signal::ctrl_c().await.expect("failed to listen for event");
        Ok(())
        // let running = Arc::new(AtomicBool::new(true));
        // let r = running.clone();
        //
        // ctrlc::set_handler(move || {
        //     r.store(false, Ordering::SeqCst);
        // })
        // .expect("Error setting Ctrl-C handler");
        //
        // println!("Waiting for Ctrl-C...");
        // while running.load(Ordering::SeqCst) {
        //     thread::sleep(Duration::from_millis(500))
        // }
        // println!("Exiting...");
        //
        // Ok(())
    } else {
        // DEPLICATED CODE
        tc::qdisc_add_clsact(&opt.iface)?;
        let program: &mut SchedClassifier = bpf.program_mut("bdc").unwrap().try_into()?;
        program.load()?;
        program.attach(&opt.iface, TcAttachType::Ingress)?;

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");

        println!("Waiting for Ctrl-C...");
        while running.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(500))
        }
        println!("Exiting...");

        Ok(())
    }
}

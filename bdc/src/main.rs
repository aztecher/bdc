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
    },
    include_bytes_aligned,
    Bpf,
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
use structopt::StructOpt;
use tokio::{signal, task};

// #[tokio::main]
// async fn main() {
fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long, default_value = "eth0")]
    iface: String,
    #[structopt(short, long, default_value = "xdp")]
    bpftype: String,
}

fn try_main() -> Result<(), anyhow::Error> {
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
        let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).try_into()?;
        blocklist.insert(block_addr, 0, 0)?;

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
    } else {
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

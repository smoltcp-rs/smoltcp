use std::str::{self, FromStr};
use std::env;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use std::process;
use log::{LogLevelFilter, LogRecord};
use env_logger::{LogBuilder};
use getopts;

use smoltcp::phy::{Tracer, FaultInjector, TapInterface};
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::PrettyPrinter;

pub fn setup_logging() {
    let startup_time = Instant::now();
    LogBuilder::new()
        .format(move |record: &LogRecord| {
            let elapsed = Instant::now().duration_since(startup_time);
            if record.target().starts_with("smoltcp::") {
                format!("\x1b[0m[{:6}.{:03}s] ({}): {}\x1b[0m",
                        elapsed.as_secs(), elapsed.subsec_nanos() / 1000000,
                        record.target().replace("smoltcp::", ""), record.args())
            } else {
                format!("\x1b[32m[{:6}.{:03}s] ({}): {}\x1b[0m",
                        elapsed.as_secs(), elapsed.subsec_nanos() / 1000000,
                        record.target(), record.args())
            }
        })
        .filter(None, LogLevelFilter::Trace)
        .init()
        .unwrap();
}

pub fn setup_device(more_args: &[&str])
        -> (Tracer<FaultInjector<TapInterface>, EthernetFrame<&'static [u8]>>,
            Vec<String>) {
    let mut opts = getopts::Options::new();
    opts.optopt("", "drop-chance", "Chance of dropping a packet (%)", "CHANCE");
    opts.optopt("", "corrupt-chance", "Chance of corrupting a packet (%)", "CHANCE");
    opts.optflag("h", "help", "print this help menu");

    let matches = opts.parse(env::args().skip(1)).unwrap();
    if matches.opt_present("h") || matches.free.len() != more_args.len() + 1 {
        let brief = format!("Usage: {} INTERFACE {} [options]",
                            env::args().nth(0).unwrap(),
                            more_args.join(" "));
        print!("{}", opts.usage(&brief));
        process::exit(if matches.free.len() != more_args.len() + 1 { 1 } else { 0 });
    }
    let drop_chance    = u8::from_str(&matches.opt_str("drop-chance")
                                             .unwrap_or("0".to_string())).unwrap();
    let corrupt_chance = u8::from_str(&matches.opt_str("corrupt-chance")
                                             .unwrap_or("0".to_string())).unwrap();

    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();

    fn trace_writer(printer: PrettyPrinter<EthernetFrame<&[u8]>>) {
        print!("\x1b[37m{}\x1b[0m", printer)
    }

    let device = TapInterface::new(&matches.free[0]).unwrap();
    let mut device = FaultInjector::new(device, seed);
    device.set_drop_chance(drop_chance);
    device.set_corrupt_chance(corrupt_chance);
    let device = Tracer::<_, EthernetFrame<&'static [u8]>>::new(device, trace_writer);

    (device, matches.free[1..].to_owned())
}

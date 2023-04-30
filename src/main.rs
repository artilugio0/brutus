use clap::{Parser, Subcommand};

const DEFAULT_PORT_RANGE: &str = "1-65535";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Brute force an HTTP endpoint
    Http {
        /// Path to a file containing raw HTTP request
        #[arg(short = 'R', long)]
        raw_request: String,

        /// Status code to be considered a success
        #[arg(short, long)]
        status: Option<u32>,

        /// String to be found in the response body to be considered a success
        #[arg(short, long)]
        body: Option<String>,

        /// String NOT to be found in the response body to be considered a success
        #[arg(short = 'B', long)]
        not_body: Option<String>,

        /// Target to be brute forced
        #[arg(short, long)]
        target: String,

        /// Path to a file containing list of values to be used
        #[arg(short, long)]
        wordlist: String,

        /// Amount of attempts per second
        #[arg(short, long, default_value_t = 10)]
        rate: u32,
    },

    /// Port scan a host
    PortScan {
        /// Target to be brute forced
        #[arg(short, long)]
        target: String,

        /// Amount of attempts per second
        #[arg(short, long, default_value_t = 10)]
        rate: u32,

        /// Range of ports to be scanned
        #[arg(short, long, default_value_t = DEFAULT_PORT_RANGE.to_string())]
        port_range: String,
    },
}

fn main() {
    let args = Args::parse();

    match args.command {
        Commands::Http {
            raw_request,
            status,
            body,
            not_body,
            target,
            wordlist,
            rate,
        } => http_brute_force(raw_request, status, body, not_body, target, wordlist, rate),

        Commands::PortScan {
            target,
            rate,
            port_range,
        } => port_scan(target, rate, port_range),
    }
}

fn http_brute_force(
    request: String,
    status: Option<u32>,
    body: Option<String>,
    not_body: Option<String>,
    target: String,
    wordlist: String,
    rate: u32,
) {
    println!("Http");
    println!("\trequest: {}", request);
    println!("\tstatus: {:?}", status);
    println!("\tbody: {:?}", body);
    println!("\tnot_body: {:?}", not_body);
    println!("\ttarget: {}", target);
    println!("\twordlist: {}", wordlist);
    println!("\trate: {}", rate);
}

fn port_scan(target: String, rate: u32, port_range: String) {
    println!("PortScan");
    println!("\ttarget: {}", target);
    println!("\trate: {}", rate);
    println!("\tport_range: {}", port_range);
}

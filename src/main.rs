use async_channel::{bounded, Receiver, Sender};
use clap::{Parser, Subcommand};
use std::sync;

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

async fn rate_limiting_requests(
    reqs_per_sec: u32,
) -> (
    Sender<reqwest::Request>,
    Receiver<Result<reqwest::Response, reqwest::Error>>,
) {
    let (request_tx, request_rx) = bounded::<reqwest::Request>(1);
    let (responses_tx, responses_rx) = bounded::<Result<reqwest::Response, reqwest::Error>>(1);

    let client = reqwest::Client::new();

    let ongoing_requests = sync::Arc::new(tokio::sync::Mutex::new(0));

    for _ in 0..reqs_per_sec {
        let request_rx = request_rx.clone();
        let responses_tx = responses_tx.clone();
        let client = client.clone();
        let ongoing_requests = ongoing_requests.clone();

        tokio::spawn(async move {
            while let Ok(request) = request_rx.recv().await {
                // wait until we have less than reqs_per_sec ongoing requests
                loop {
                    {
                        let mut ongoing_requests = ongoing_requests.lock().await;
                        if *ongoing_requests >= reqs_per_sec {
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            continue;
                        }

                        *ongoing_requests += 1;
                        eprintln!("ongoing requests: {}", *ongoing_requests);
                        break;
                    }
                }

                // make the request
                let req = request.try_clone().unwrap();
                let mut result = client.execute(req).await;
                for _retry in 0..3 {
                    if result.is_ok() {
                        break;
                    }

                    eprintln!("retrying...");

                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    let req = request.try_clone().unwrap();
                    result = client.execute(req).await;
                }

                {
                    let mut ongoing_requests = ongoing_requests.lock().await;
                    *ongoing_requests -= 1;
                }

                responses_tx.send(result).await.unwrap();
            }
        });
    }

    (request_tx, responses_rx)
}

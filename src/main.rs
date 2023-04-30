use async_channel::{bounded, Receiver, Sender};
use clap::{Parser, Subcommand};
use std::{collections::HashMap, sync};
use tokio::io::AsyncReadExt;

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

#[tokio::main]
async fn main() {
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
        } => http_brute_force(raw_request, status, body, not_body, target, wordlist, rate).await,

        Commands::PortScan {
            target,
            rate,
            port_range,
        } => port_scan(target, rate, port_range).await,
    }
}

async fn http_brute_force(
    raw_request_path: String,
    status: Option<u32>,
    body: Option<String>,
    not_body: Option<String>,
    target: String,
    wordlist: String,
    rate: u32,
) {
    println!("Http");
    println!("\traw_request_path: {}", raw_request_path);
    println!("\tstatus: {:?}", status);
    println!("\tbody: {:?}", body);
    println!("\tnot_body: {:?}", not_body);
    println!("\ttarget: {}", target);
    println!("\twordlist: {}", wordlist);
    println!("\trate: {}", rate);

    // Read the raw request from the file
    let mut req_file = tokio::fs::File::open(raw_request_path).await.unwrap();
    let mut raw_request = Vec::new();
    req_file.read_to_end(&mut raw_request).await.unwrap();

    // Parse request
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let bytes_read = req.parse(&raw_request).unwrap().unwrap();

    let content_length = req
        .headers
        .iter()
        .filter(|&h| h.name.to_lowercase() == "content-length")
        .next()
        .unwrap()
        .value;

    let content_length = String::from_utf8(content_length.to_vec())
        .unwrap()
        .parse::<usize>()
        .unwrap();

    // Build reqwest::Request
    let url = reqwest::Url::parse(&target)
        .unwrap()
        .join(req.path.unwrap())
        .unwrap();

    let mut request = reqwest::Request::new(req.method.unwrap().try_into().unwrap(), url);

    let mut headers = HashMap::new();
    for h in req.headers.iter() {
        headers.insert(
            h.name.to_string(),
            String::from_utf8_lossy(h.value).to_string(),
        );
    }
    let headers: reqwest::header::HeaderMap = (&headers).try_into().unwrap();
    request.headers_mut().extend(headers);

    let request_body = request.body_mut();
    let body = raw_request[bytes_read..bytes_read + content_length]
        .to_vec()
        .into();
    *request_body = Some(body);

    eprintln!("reqwest request: {request:?}");
    eprintln!("reqwest body: {:?}", request.body().unwrap().as_bytes());

    let (req_tx, resp_rx) = rate_limiting_requests(rate);
    req_tx.send(request).await.unwrap();
    let response = resp_rx.recv().await;

    eprintln!("response: {response:?}");
}

async fn port_scan(target: String, rate: u32, port_range: String) {
    println!("PortScan");
    println!("\ttarget: {}", target);
    println!("\trate: {}", rate);
    println!("\tport_range: {}", port_range);
}

fn rate_limiting_requests(
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

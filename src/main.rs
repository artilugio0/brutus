use async_channel::{bounded, Receiver, Sender};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
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
        status: Option<u16>,

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
    status: Option<u16>,
    body: Option<String>,
    not_body: Option<String>,
    target: String,
    wordlist_path: String,
    rate: u32,
) {
    // Read the contents of the wordlist
    let mut wordlist_contents = String::new();
    let mut wordlist_file = tokio::fs::File::open(wordlist_path).await.unwrap();
    wordlist_file
        .read_to_string(&mut wordlist_contents)
        .await
        .unwrap();
    let wordlist = wordlist_contents
        .lines()
        .map(|l| l.trim_end())
        .collect::<Vec<_>>();

    // Read the raw request from the file
    let mut req_file = tokio::fs::File::open(raw_request_path).await.unwrap();
    let mut raw_request = Vec::new();
    req_file.read_to_end(&mut raw_request).await.unwrap();

    let (req_tx, resp_rx) = rate_limiting_requests(rate);

    let req_count = wordlist.len();
    let resp_rx = resp_rx.clone();
    let handle = tokio::spawn(async move {
        for _ in 0..req_count {
            let (response_result, word) = resp_rx.recv().await.unwrap();
            let response = response_result.unwrap();

            if let Some(status) = status {
                if response.status().as_u16() != status {
                    eprintln!("{word}\t\t\t\tFAILED");
                    continue;
                }
            }

            let body_bytes = response.bytes().await.unwrap();
            let body_string = String::from_utf8_lossy(&body_bytes);

            if let Some(body_content) = body.clone() {
                if !body_string.contains(&body_content) {
                    eprintln!("{word}\t\t\t\tFAILED");
                    continue;
                }
            }

            if let Some(not_body_content) = not_body.clone() {
                if body_string.contains(&not_body_content) {
                    eprintln!("{word}\t\t\t\tFAILED");
                    continue;
                }
            }

            eprintln!("{word}\t\t\t\tSUCCESS");
        }
    });

    for word in wordlist.into_iter() {
        // Parse request
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        let raw_request = String::from_utf8_lossy(&raw_request)
            .trim_end()
            .replace("FUZZ", word);
        let raw_request = raw_request.as_bytes();

        let bytes_read = req.parse(&raw_request).unwrap().unwrap();

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
        let body = raw_request[bytes_read..].to_vec().into();
        *request_body = Some(body);

        req_tx.send((request, word.to_string())).await.unwrap();
    }

    handle.await.unwrap();
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
    Sender<(reqwest::Request, String)>,
    Receiver<(Result<reqwest::Response, reqwest::Error>, String)>,
) {
    let (request_tx, request_rx) = bounded::<(reqwest::Request, String)>(1);
    let (responses_tx, responses_rx) =
        bounded::<(Result<reqwest::Response, reqwest::Error>, String)>(1);

    let client = reqwest::Client::new();

    for _ in 0..reqs_per_sec {
        let request_rx = request_rx.clone();
        let responses_tx = responses_tx.clone();
        let client = client.clone();

        tokio::spawn(async move {
            let mut last_request = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap();

            while let Ok((request, word)) = request_rx.recv().await {
                let time_since_last_request = last_request.elapsed().as_millis();
                if time_since_last_request < 1000 {
                    let remaining_waiting_time = 1000 - time_since_last_request as u64;
                    let sleep_time = std::time::Duration::from_millis(remaining_waiting_time);
                    tokio::time::sleep(sleep_time).await;
                }

                // make the request
                let req = request.try_clone().unwrap();
                let mut result = client.execute(req).await;
                for _retry in 0..3 {
                    if result.is_ok() {
                        break;
                    }

                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    let req = request.try_clone().unwrap();
                    result = client.execute(req).await;
                }
                last_request = std::time::Instant::now();

                responses_tx.send((result, word)).await.unwrap();
            }
        });
    }

    (request_tx, responses_rx)
}

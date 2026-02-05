use chrono::Utc;
use clap::Parser;
use futures::future;
use hyper::{server::conn::http1, service::service_fn, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use prometheus::Registry;
use rdsys_backend::{proto::ResourceState, request_resources};
use serde::Deserialize;

use std::{
    fs::File,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

mod db_handler;
use db_handler::{DAYS_OF_STORAGE, DB};
mod command;
use command::Command;
mod fake_resource_state;
mod lox_context;
mod metrics;
use metrics::Metrics;
mod request_handler;
use request_handler::handle;
mod resource_parser;
use resource_parser::{parse_into_bridgelines, parse_into_buckets};

use tokio::{
    signal, spawn,
    sync::{broadcast, mpsc, oneshot},
    time::{interval, sleep},
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name/path of the configuration file
    #[arg(short, long, default_value = "config.json")]
    config: PathBuf,

    // Optional Date/time to roll back to as a %Y-%m-%d_%H:%M:%S string
    // This argument should be passed if the lox_context should be rolled back to a
    // previous state due to, for example, a mass blocking event that is likely not
    // due to Lox user behaviour. If the exact roll back date/time is not known, the
    // last db entry within 24 hours from the passed roll_back_date will be used or else
    // the program will fail gracefully.
    #[arg(short, long, verbatim_doc_comment)]
    roll_back_date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Config {
    db: DbConfig,
    metrics_port: u16,
    lox_authority_port: u16,
    bridge_config: BridgeConfig,
    rtype: ResourceInfo,
}

// Path of the lox database
#[derive(Debug, Deserialize)]
pub struct DbConfig {
    // The path for the lox_context database, default is "lox_db"
    db_path: String,
}

impl Default for DbConfig {
    fn default() -> DbConfig {
        DbConfig {
            db_path: "lox_db".to_owned(),
        }
    }
}

// Config information for how bridges should be allocated to buckets
#[derive(Clone, Debug, Default, Deserialize)]
pub struct BridgeConfig {
    // A list of regions (as ISO 3166 country codes) that Lox will monitor resources for.
    // Any region indicated here that is listed in the `blocked_in` field of a resource will be marked as
    // blocked by Lox's bridge authority.
    watched_blockages: Vec<String>,
    // The percentage of buckets (made up of MAX_BRIDGES_PER_BUCKET bridges)
    // that should be allocated as spare buckets
    // This will be calculated as the floor of buckets.len() * percent_spares / 100
    percent_spares: i32,
}

#[derive(Debug, Deserialize)]
struct ResourceInfo {
    endpoint: String,
    name: String,
    token: String,
    types: Vec<String>,
    request_interval: u64,
}
// Populate Bridgedb from rdsys

// Rdsys sender creates a Resource request with the api_endpoint, resource token and type specified
// in the config.json file.
async fn rdsys_request_creator(
    rtype: ResourceInfo,
    tx: mpsc::Sender<ResourceState>,
    mut kill: broadcast::Receiver<()>,
) {
    tokio::select! {
        start_resource_request = rdsys_request(rtype, tx) => start_resource_request,
        _ = kill.recv() => {println!("Shut down rdsys request loop")},

    }
}

// Makes a request to rdsys for the full set of Resources assigned to lox every interval
// (defined in the function)
async fn rdsys_request(rtype: ResourceInfo, tx: mpsc::Sender<ResourceState>) {
    let mut interval = interval(Duration::from_secs(rtype.request_interval));
    loop {
        interval.tick().await;
        let resources = match request_resources(
            rtype.endpoint.clone(),
            rtype.name.clone(),
            rtype.token.clone(),
            rtype.types.clone(),
        )
        .await
        {
            Ok(resources) => resources,
            Err(e) => {
                println!("No resources received from rdsys: {e:?}");
                continue;
            }
        };
        if let Err(err) = tx.send(resources).await {
            println!("Error sending ResourceState to bridge parser receiver: {err}")
        };
    }
}

// Parse bridges received from rdsys and sync with Lox context
async fn rdsys_bridge_parser(
    rdsys_tx: mpsc::Sender<Command>,
    rx: mpsc::Receiver<ResourceState>,
    mut kill: broadcast::Receiver<()>,
) {
    tokio::select! {
        start_bridge_parser = parse_bridges(rdsys_tx, rx) => start_bridge_parser ,
        _ = kill.recv() => {println!("Shut down bridge_parser");},
    }
}

// Parse Bridges receives the resources from rdsys and sends it to the
// Context Manager to be parsed and added to the Lox BridgeDB
async fn parse_bridges(rdsys_tx: mpsc::Sender<Command>, mut rx: mpsc::Receiver<ResourceState>) {
    loop {
        if let Some(resources) = rx.recv().await {
            let cmd = Command::Rdsys { resources };
            if let Err(err) = rdsys_tx.send(cmd).await {
                println!("Error sending resources to Lox BridgeDB: {err}")
            }

            sleep(Duration::from_secs(1)).await;
        }
    }
}

// Create a prometheus metrics server
async fn start_metrics_collector(
    metrics_addr: SocketAddr,
    registry: Registry,
    mut kill: broadcast::Receiver<()>,
) {
    tokio::select! {
        lox_metrics = metrics::start_metrics_server(metrics_addr, registry) => lox_metrics,
        _ = kill.recv() => {println!("Shut down metrics server");},
    }
}

async fn create_context_manager(
    db_config: DbConfig,
    bridge_config: BridgeConfig,
    roll_back_date: Option<String>,
    metrics: Metrics,
    context_rx: mpsc::Receiver<Command>,
    mut kill: broadcast::Receiver<()>,
) {
    tokio::select! {
        create_context = context_manager(db_config, bridge_config, roll_back_date, metrics, context_rx) => create_context,
        _ = kill.recv() => {println!("Shut down context_manager");},
    }
}

// Context Manager handles the Lox BridgeDB and Bridge Authority, ensuring
// that the DB can be updated from the rdsys stream and client requests
// can be responded to with an updated BridgeDB state
async fn context_manager(
    db_config: DbConfig,
    bridge_config: BridgeConfig,
    roll_back_date: Option<String>,
    metrics: Metrics,
    mut context_rx: mpsc::Receiver<Command>,
) {
    let (mut lox_db, context) =
        match DB::open_new_or_existing_db(db_config, roll_back_date.clone(), metrics) {
            Ok((lox_db, context)) => (lox_db, context),
            Err(e) => {
                panic!("Error: {e}");
            }
        };
    // Clear entries that are more than roll_back_date - DAYS_OF_STORAGE(14)
    // days old
    let mut clear_entry_time = lox_db.clear_old_entries(roll_back_date);

    while let Some(cmd) = context_rx.recv().await {
        use Command::*;
        match cmd {
            Rdsys { resources } => {
                // If the bridgetable is not being loaded from an existing database, we will populate the
                // bridgetable with all of the working bridges received from rdsys.
                if context.bridgetable_is_empty() {
                    if let Some(working_resources) = resources.working {
                        let (bridgelines, _) = parse_into_bridgelines(
                            bridge_config.watched_blockages.clone(),
                            working_resources,
                        );
                        context.metrics.new_bridges.inc_by(bridgelines.len() as f64);
                        let (buckets, leftovers) = parse_into_buckets(bridgelines);
                        for leftover in leftovers {
                            context.append_extra_bridges(leftover);
                        }
                        context.populate_bridgetable(buckets, bridge_config.percent_spares);

                        // otherwise, we need to sync the existing bridgetable with the resources we receive from
                        // rdsys and ensure that all functioning bridges are correctly placed in the bridgetable
                        // those that have changed are updated and those that have been failing tests for an extended
                        // period of time are removed.
                        // If bridges are labelled as blocked_in, we should also handle blocking behaviour.
                    }
                } else {
                    context.sync_with_bridgetable(
                        bridge_config.clone().watched_blockages,
                        bridge_config.percent_spares,
                        resources,
                    );
                }
                // Handle any bridges that are leftover in the bridge authority from the sync
                context.allocate_leftover_bridges();
                context.encrypt_table();
                lox_db.write_context(context.clone());
                if (Utc::now() - clear_entry_time).num_days() > DAYS_OF_STORAGE as i64 {
                    clear_entry_time = lox_db.clear_old_entries(None);
                }
                sleep(Duration::from_millis(1)).await;
            }
            Request { req, sender } => {
                let response = handle(context.clone(), req).await;
                let result = response
                    .as_ref()
                    .is_ok_and(|response| response.status() != StatusCode::NOT_FOUND);
                if let Err(e) = sender.send(response) {
                    eprintln!("Server Response Error: {e:?}");
                } else if result {
                    lox_db.write_context(context.clone());
                }
                sleep(Duration::from_millis(1)).await;
            }
            Shutdown { shutdown_sig } => {
                lox_db.write_context(context.clone());
                println!("Sending Shutdown Signal, all threads should shutdown.");
                drop(shutdown_sig);
                println!("Shutdown Sent.");
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let args: Args = Args::parse();

    let file = File::open(&args.config).expect("Could not read config file");
    let reader = BufReader::new(file);
    // Read the JSON contents of the file as a ResourceInfo
    let config: Config = serde_json::from_reader(reader).expect("Reading Config from JSON failed.");

    let (rdsys_tx, context_rx) = mpsc::channel(32);
    let request_tx = rdsys_tx.clone();
    let shutdown_cmd_tx = rdsys_tx.clone();

    // create the shutdown broadcast channel and clone for every thread
    let (shutdown_tx, mut shutdown_rx) = broadcast::channel(16);
    let kill_stream = shutdown_tx.subscribe();
    let kill_metrics = shutdown_tx.subscribe();
    let kill_parser = shutdown_tx.subscribe();
    let kill_context = shutdown_tx.subscribe();
    let mut kill_requests = shutdown_tx.subscribe();

    // Listen for ctrl_c, send signal to broadcast shutdown to all threads by dropping shutdown_tx
    let shutdown_handler = spawn(async move {
        tokio::select! {
            _ = signal::ctrl_c() => {
                let cmd = Command::Shutdown {
                    shutdown_sig: shutdown_tx,
                };
                shutdown_cmd_tx.send(cmd).await.unwrap();
                sleep(Duration::from_secs(1)).await;

               _ = shutdown_rx.recv().await;
            }
        }
    });

    let metrics = Metrics::default();
    let registry = metrics.register();
    let metrics_addr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), config.metrics_port);
    let metrics_handler =
        spawn(async move { start_metrics_collector(metrics_addr, registry, kill_metrics).await });

    let context_manager = spawn(async move {
        create_context_manager(
            config.db,
            config.bridge_config,
            args.roll_back_date,
            metrics,
            context_rx,
            kill_context,
        )
        .await
    });

    let (tx, rx) = mpsc::channel(32);
    let rdsys_request_handler =
        spawn(async { rdsys_request_creator(config.rtype, tx, kill_stream).await });

    let rdsys_resource_receiver =
        spawn(async { rdsys_bridge_parser(rdsys_tx, rx, kill_parser).await });

    let addr = SocketAddr::from(([127, 0, 0, 1], config.lox_authority_port));

    let listener = TcpListener::bind(addr).await.expect("failed to bind");

    let svc_fn = move |req| {
        let request_tx = request_tx.clone();
        let (response_tx, response_rx) = oneshot::channel();
        let cmd = Command::Request {
            req,
            sender: response_tx,
        };
        async move {
            if let Err(err) = request_tx.send(cmd).await {
                println!("Error sending http request to handler: {err}");
            }
            response_rx.await.unwrap()
        }
    };

    let request_handler = spawn(async move {
        loop {
            tokio::select! {
                res = listener.accept() => {
                    let (stream, _) = res.expect("Failed to accept");
                    let io = TokioIo::new(stream);
                    let handler = svc_fn.clone();
                    spawn(async move {
                        if let Err(err) = http1::Builder::new().serve_connection(io, service_fn(handler)).await {
                            println!("Error serving connection: {err}");
                        }
                    });
                }
                _ = kill_requests.recv() => {
                    println!("Shut down request_handler");
                    break;
                }
            }
        }
    });

    future::join_all([
        metrics_handler,
        rdsys_request_handler,
        rdsys_resource_receiver,
        context_manager,
        shutdown_handler,
        request_handler,
    ])
    .await;
}

use prometheus::{Counter, Opts, Registry};
use prometheus_hyper::Server;
use std::{net::SocketAddr, sync::Arc};

#[derive(Debug, Clone)]
pub struct Metrics {
    pub existing_or_updated_bridges: Counter,
    pub new_bridges: Counter,
    pub removed_bridges: Counter,
    pub blocked_bridges: Counter,
    pub open_inv_count: Counter,
    pub trust_promo_count: Counter,
    pub trust_mig_count: Counter,
    pub level_up_count: Counter,
    pub issue_invite_count: Counter,
    pub redeem_invite_count: Counter,
    pub check_blockage_count: Counter,
    pub blockage_migration_count: Counter,
    pub update_cred_count: Counter,
    pub update_invite_count: Counter,
    pub k_reset_count: Counter,
    pub invites_requested: Counter,
    pub invalid_endpoint_request_count: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        // Create counters.
        let existing_or_updated_bridges = Counter::with_opts(Opts::new(
            "existing_or_updated_bridges",
            "number of bridges that were already in the bridgetable and may have been updated",
        ))
        .unwrap();
        let new_bridges =
            Counter::with_opts(Opts::new("new_bridges", "number of newly added bridges")).unwrap();
        let removed_bridges = Counter::with_opts(Opts::new("removed_bridges", "number of bridges that have been removed from the bridgetable due to being down for an extended period")).unwrap();
        let blocked_bridges = Counter::with_opts(Opts::new(
            "blocked_bridges",
            "number of bridges that are blocked",
        ))
        .unwrap();
        let open_inv_count = Counter::with_opts(Opts::new(
            "open_inv_count",
            "number of open invitations distributed",
        ))
        .unwrap();
        let trust_promo_count = Counter::with_opts(Opts::new(
            "trust_promo_count",
            "number of trust promotion requests",
        ))
        .unwrap();
        let trust_mig_count = Counter::with_opts(Opts::new(
            "trust_mig_count",
            "number of trust migration requests",
        ))
        .unwrap();
        let level_up_count =
            Counter::with_opts(Opts::new("level_up_count", "number of level up requests")).unwrap();
        let issue_invite_count = Counter::with_opts(Opts::new(
            "issue_invite_count",
            "number of issue invite requests",
        ))
        .unwrap();
        let redeem_invite_count = Counter::with_opts(Opts::new(
            "redeem_invite_count",
            "number of redeem invite requests",
        ))
        .unwrap();
        let check_blockage_count = Counter::with_opts(Opts::new(
            "check_blockage_count",
            "number of check blockage requests",
        ))
        .unwrap();
        let blockage_migration_count = Counter::with_opts(Opts::new(
            "blockage_migration_count",
            "number of blockage migration requests",
        ))
        .unwrap();
        let update_cred_count = Counter::with_opts(Opts::new(
            "update_cred_count",
            "number of update cred requests",
        ))
        .unwrap();
        let update_invite_count = Counter::with_opts(Opts::new(
            "update_invite_count",
            "number of update invite requests",
        ))
        .unwrap();
        let k_reset_count = Counter::with_opts(Opts::new(
            "k_reset_count",
            "number of trust migration requests",
        ))
        .unwrap();
        let invites_requested = Counter::with_opts(Opts::new(
            "invites_requested",
            "number of trust migration requests",
        ))
        .unwrap();
        let invalid_endpoint_request_count = Counter::with_opts(Opts::new(
            "invalid_endpoint_request_count",
            "number of requests made to an invalid or non-existent endpoint",
        ))
        .unwrap();

        Metrics {
            existing_or_updated_bridges,
            new_bridges,
            removed_bridges,
            blocked_bridges,
            open_inv_count,
            trust_promo_count,
            trust_mig_count,
            level_up_count,
            issue_invite_count,
            redeem_invite_count,
            check_blockage_count,
            blockage_migration_count,
            update_cred_count,
            update_invite_count,
            k_reset_count,
            invites_requested,
            invalid_endpoint_request_count,
        }
    }
}

impl Metrics {
    pub fn register(&self) -> Registry {
        // Create a Registry and register Counter.
        let r = <Registry>::new_custom(Some("lox-metrics".to_owned()), None).unwrap();
        r.register(Box::new(self.existing_or_updated_bridges.clone()))
            .unwrap();
        r.register(Box::new(self.new_bridges.clone())).unwrap();
        r.register(Box::new(self.removed_bridges.clone())).unwrap();
        r.register(Box::new(self.blocked_bridges.clone())).unwrap();
        r.register(Box::new(self.open_inv_count.clone())).unwrap();
        r.register(Box::new(self.trust_promo_count.clone()))
            .unwrap();
        r.register(Box::new(self.trust_mig_count.clone())).unwrap();
        r.register(Box::new(self.level_up_count.clone())).unwrap();
        r.register(Box::new(self.issue_invite_count.clone()))
            .unwrap();
        r.register(Box::new(self.redeem_invite_count.clone()))
            .unwrap();
        r.register(Box::new(self.check_blockage_count.clone()))
            .unwrap();
        r.register(Box::new(self.blockage_migration_count.clone()))
            .unwrap();
        r.register(Box::new(self.update_cred_count.clone()))
            .unwrap();
        r.register(Box::new(self.update_invite_count.clone()))
            .unwrap();
        r.register(Box::new(self.k_reset_count.clone())).unwrap();
        r.register(Box::new(self.invites_requested.clone()))
            .unwrap();
        r
    }
}

/// Start a HTTP server to report metrics.
pub async fn start_metrics_server(metrics_addr: SocketAddr, registry: Registry) {
    eprintln!("Starting metrics server on {metrics_addr}");

    let registry = Arc::new(registry);
    tokio::spawn(Server::run(
        Arc::clone(&registry),
        metrics_addr,
        std::future::pending(),
    ));
}

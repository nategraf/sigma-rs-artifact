use std::convert::Infallible;

use http_body_util::combinators::BoxBody;
use hyper::{
    body::{Bytes, Incoming},
    Request, Response,
};
use rdsys_backend::proto::ResourceState;
use tokio::sync::{broadcast, oneshot};

// Each of the commands that the Context Manager handles
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Command {
    Rdsys {
        resources: ResourceState,
    },
    Request {
        req: Request<Incoming>,
        sender: oneshot::Sender<Result<Response<BoxBody<Bytes, Infallible>>, Infallible>>,
    },
    Shutdown {
        shutdown_sig: broadcast::Sender<()>,
    },
}

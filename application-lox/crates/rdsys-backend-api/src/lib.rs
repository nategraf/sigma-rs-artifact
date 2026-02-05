//! # Rdsys Backend Distributor API
//!
//! `rdsys_backend` is an implementation of the rdsys backend API
//! https://gitlab.torproject.org/tpo/anti-censorship/rdsys/-/blob/main/doc/backend-api.md

use bytes::{self, Buf, Bytes};
use core::pin::Pin;
use futures_util::{Stream, StreamExt};
use reqwest::{Client, StatusCode};
use std::io::{self, BufRead};
use std::task::{ready, Context, Poll};
use tokio::sync::mpsc;
use tokio_util::sync::ReusableBoxFuture;

pub mod proto;

#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    Io(io::Error),
    JSON(serde_json::Error),
    String(StatusCode),
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::JSON(value)
    }
}

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        Self::Reqwest(value)
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// An iterable wrapper of ResourceDiff items for the streamed chunks of Bytes
/// received from the connection to the rdsys backend
pub struct ResourceStream {
    inner: ReusableBoxFuture<'static, (Option<Bytes>, mpsc::Receiver<Bytes>)>,
    buf: Vec<u8>,
    partial: Option<bytes::buf::Reader<Bytes>>,
}

impl ResourceStream {
    pub fn new(rx: mpsc::Receiver<Bytes>) -> ResourceStream {
        ResourceStream {
            inner: ReusableBoxFuture::new(make_future(rx)),
            buf: vec![],
            partial: None,
        }
    }
}

async fn make_future(mut rx: mpsc::Receiver<Bytes>) -> (Option<Bytes>, mpsc::Receiver<Bytes>) {
    let result = rx.recv().await;
    (result, rx)
}

impl Stream for ResourceStream {
    type Item = proto::ResourceDiff;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let parse = |buffer: &mut bytes::buf::Reader<Bytes>,
                     buf: &mut Vec<u8>|
         -> Result<Option<Self::Item>, Error> {
            match buffer.read_until(b'\r', buf) {
                Ok(_) => match buf.pop() {
                    Some(b'\r') => match serde_json::from_slice(buf) {
                        Ok(diff) => {
                            buf.clear();
                            Ok(Some(diff))
                        }
                        Err(e) => Err(Error::JSON(e)),
                    },
                    Some(n) => {
                        buf.push(n);
                        Ok(None)
                    }
                    None => Ok(None),
                },
                Err(e) => Err(Error::Io(e)),
            }
        };
        // This clone is here to avoid having multiple mutable references to self
        // it's not optimal performance-wise but given that these resource streams aren't large
        // this feels like an acceptable trade-off to the complexity of interior mutability
        let mut buf = self.buf.clone();
        if let Some(p) = &mut self.partial {
            match parse(p, &mut buf) {
                Ok(Some(diff)) => return Poll::Ready(Some(diff)),
                Ok(None) => self.partial = None,
                Err(_) => return Poll::Ready(None),
            }
        }
        self.buf = buf;
        loop {
            let (result, rx) = ready!(self.inner.poll(cx));
            self.inner.set(make_future(rx));
            match result {
                Some(chunk) => {
                    let mut buffer = chunk.reader();
                    match parse(&mut buffer, &mut self.buf) {
                        Ok(Some(diff)) => {
                            self.partial = Some(buffer);
                            return Poll::Ready(Some(diff));
                        }
                        Ok(None) => continue,
                        Err(_) => return Poll::Ready(None),
                    }
                }
                None => return Poll::Ready(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_resource() {
        let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
        let chunk = Bytes::from_static(
            b"{\"new\": null,\"changed\": null,\"gone\": null,\"full_update\": true}\r",
        );
        let (tx, rx) = mpsc::channel(100);
        tx.send(chunk).await.unwrap();
        let mut diffs = ResourceStream::new(rx);
        let res = Pin::new(&mut diffs).poll_next(&mut cx);
        assert_ne!(res, Poll::Ready(None));
        assert_ne!(res, Poll::Pending);
        if let Poll::Ready(Some(diff)) = res {
            assert_eq!(diff.new, None);
            assert!(diff.full_update);
        }
    }

    #[tokio::test]
    async fn parse_across_chunks() {
        let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
        let chunk1 = Bytes::from_static(b"{\"new\": null,\"changed\": null,");
        let chunk2 = Bytes::from_static(b"\"gone\": null,\"full_update\": true}\r");
        let (tx, rx) = mpsc::channel(100);
        tx.send(chunk1).await.unwrap();
        tx.send(chunk2).await.unwrap();
        let mut diffs = ResourceStream::new(rx);
        let mut res = Pin::new(&mut diffs).poll_next(&mut cx);
        while res.is_pending() {
            res = Pin::new(&mut diffs).poll_next(&mut cx);
        }
        assert_ne!(res, Poll::Ready(None));
        assert_ne!(res, Poll::Pending);
        if let Poll::Ready(Some(diff)) = res {
            assert_eq!(diff.new, None);
            assert!(diff.full_update);
        }
    }

    #[tokio::test]
    async fn parse_multi_diff_partial_chunks() {
        let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
        let chunk1 = Bytes::from_static(b"{\"new\": null,\"changed\": null,");
        let chunk2 =
            Bytes::from_static(b"\"gone\": null,\"full_update\": true}\r{\"new\": null,\"changed");
        let chunk3 = Bytes::from_static(b"\": null,\"gone\": null,\"full_update\": true}");
        let chunk4 = Bytes::from_static(b"\r");
        let (tx, rx) = mpsc::channel(100);
        tx.send(chunk1).await.unwrap();
        tx.send(chunk2).await.unwrap();
        tx.send(chunk3).await.unwrap();
        tx.send(chunk4).await.unwrap();
        let mut diffs = ResourceStream::new(rx);
        let mut res = Pin::new(&mut diffs).poll_next(&mut cx);
        while res.is_pending() {
            res = Pin::new(&mut diffs).poll_next(&mut cx);
        }
        assert_ne!(res, Poll::Ready(None));
        assert_ne!(res, Poll::Pending);
        if let Poll::Ready(Some(diff)) = res {
            assert_eq!(diff.new, None);
            assert!(diff.full_update);
        }
        res = Pin::new(&mut diffs).poll_next(&mut cx);
        while res.is_pending() {
            res = Pin::new(&mut diffs).poll_next(&mut cx);
        }
        assert_ne!(res, Poll::Ready(None));
        assert_ne!(res, Poll::Pending);
        if let Poll::Ready(Some(diff)) = res {
            assert_eq!(diff.new, None);
            assert!(diff.full_update);
        }
    }
}

/// Makes an http connection to the rdsys backend api endpoint and returns a ResourceStream
/// if successful
///
/// # Examples
///
/// ```ignore
/// use rdsys_backend::start_stream;
///
/// let endpoint = String::from("http://127.0.0.1:7100/resource-stream");
/// let name = String::from("https");
/// let token = String::from("HttpsApiTokenPlaceholder");
/// let types = vec![String::from("obfs2"), String::from("scramblesuit")];
/// let stream = start_stream(endpoint, name, token, types).await.unwrap();
/// loop {
///     match Pin::new(&mut stream).poll_next(&mut cx) {
///         Poll::Ready(Some(diff)) => println!("Received diff: {:?}", diff),
///         Poll::Ready(None) => break,
///         Poll::Pending => continue,
///     }
/// }
/// ```
pub async fn start_stream(
    api_endpoint: String,
    name: String,
    token: String,
    resource_types: Vec<String>,
) -> Result<ResourceStream, Error> {
    let (tx, rx) = mpsc::channel(100);

    let req = proto::ResourceRequest {
        request_origin: name,
        resource_types,
    };
    let json = serde_json::to_string(&req)?;

    let auth_value = format!("Bearer {token}");

    let client = Client::new();

    let mut stream = client
        .get(api_endpoint)
        .header("Authorization", &auth_value)
        .body(json)
        .send()
        .await?
        .bytes_stream();

    tokio::spawn(async move {
        while let Some(chunk) = stream.next().await {
            let bytes = match chunk {
                Ok(b) => b,
                Err(_e) => {
                    return;
                }
            };
            tx.send(bytes).await.unwrap();
        }
    });
    Ok(ResourceStream::new(rx))
}

pub async fn request_resources(
    api_endpoint: String,
    name: String,
    token: String,
    resource_types: Vec<String>,
) -> Result<proto::ResourceState, Error> {
    let fetched_resources: Result<proto::ResourceState, Error>;
    let req = proto::ResourceRequest {
        request_origin: name,
        resource_types,
    };
    let json = serde_json::to_string(&req)?;

    let auth_value = format!("Bearer {token}");

    let client = Client::new();

    let response = client
        .get(api_endpoint)
        .header("Authorization", &auth_value)
        .body(json)
        .send()
        .await?;
    match response.status() {
        reqwest::StatusCode::OK => {
            fetched_resources = match response.json::<proto::ResourceState>().await {
                Ok(fetched_resources) => Ok(fetched_resources),
                Err(e) => Err(Error::Reqwest(e)),
            };
        }
        other => fetched_resources = Err(Error::String(other)),
    };
    fetched_resources
}

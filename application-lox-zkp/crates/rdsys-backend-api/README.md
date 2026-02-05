# rdsys backend API

The rdsys backend API allows a process to receive resources from rdsys through either of rdsys' two endpoints.

### Usage with Stream Endpoint

To test or receive a resourcediff from rdsys, the rdsys `resource-stream` endpoint can be accessed with the following sample code:

```
use rdsys_backend::start_stream;
use tokio;

#[tokio::main]
async fn main() {
    let endpoint = String::from("http://127.0.0.1:7100/resource-stream");
    let name = String::from("https");
    let token = String::from("HttpsApiTokenPlaceholder");
    let types = vec![String::from("obfs2"), String::from("scramblesuit")];
    let rx = start_stream(endpoint, name, token, types).await.unwrap();
    for diff in rx {
        println!("Received diff: {:?}", diff);
    }
}
```

### Usage with Static Request Endpoint

To test or receive a ResourceState from rdsys, the `resources` endpoint can be accessed with the following sample code:

```
use rdsys_backend::request_resources;
use tokio;

#[tokio::main]
async fn main() {
    let endpoint = String::from("http://127.0.0.1:7100/resources");
    let name = String::from("https");
    let token = String::from("HttpsApiTokenPlaceholder");
    let types = vec![String::from("obfs4"), String::from("scramblesuit")];
    let rx = request_resources(endpoint, name, token, types).await.unwrap();
    println!("Received ResourceState: {:?}", rx);
}
```
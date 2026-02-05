# lox-wasm

wasm bindings for Lox client requests and response handling. These bindings are compatible with the endpoints in the  [`lox-distributor`'s](../lox-distributor/) [`request_handler`](../lox-distributor/src/request_handler.rs).

# Dependencies

```
cargo install wasm-pack
```

# Build

```
wasm-pack build --target web
```

# Testing Locally

The provided `index.html` file can be used for testing the lox bindings. First, follow the instructions to [run the lox-distributor](../lox-distributor/README.md).

Then, spin up a simple local webserver in the current directory:
```
python3 -m http.server 8000
```

Next, open the dev console in your browser and navigate to `http://localhost:8000`.

### Note

Although all Lox protocols are implemented, they will not all work with the existing [`index.js`](index.js) and the `lox-distributor`'s `request_handler`. This is because varying time intervals must pass between successful requests for certain Lox credentials. To fully test whether or not the full set of Lox credentials are working as intended (while rejecting patience as an acceptable method), the agreed upon time between the client and server must be artificially accelerated in tandem to the required future date after each relevant request so credentials can be validated. An earlier version of the `lox-distributor`: [`lox-server`](https://gitlab.torproject.org/cohosh/lox-server/-/blob/main/src/main.rs) includes some server side examples of how to accomplish this on the server side and the `lox-wasm` crate can be edited to artificially increase the time as shown [here](https://gitlab.torproject.org/tpo/anti-censorship/lox/-/blob/73c3ef872878b295d84cddc51320d476d6fbcb7f/crates/lox-wasm/src/lib.rs#L102).

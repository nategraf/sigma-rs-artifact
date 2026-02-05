# Running Sigma-rs Experiments

### To run native-wasm tests:

#### First, collect wasm logs:

Note: If you are building outside of the sigma-rs container, you will need to follow a few build steps:
##### For rdsys
1. Clone [rdsys:](https://gitlab.torproject.org/tpo/anti-censorship/rdsys)
 2. Follow steps 1-3 in the [README for usage:](https://gitlab.torproject.org/tpo/anti-censorship/rdsys#usage)

##### For lox-wasm
1. Change into the `lox-wasm` directory and run `wasm-pack build --release --target web` to build the wasm files.

Then:

1. In the sigma-rs container, start the rdsys backend by changing into the
   rdsys directory and running: `./backend -config conf/config.json`

2. Change into the applications-lox directory

3. You will need to run the lox-distributor and the lox-wasm http server in separate terminals. First, change into the `lox-wasm` crate.

4. If you haven't built it already, run `wasm-pack build --release --target web` Then, run: `python3 -m http.server 8000`

5. Next, change into the `lox-distributor` crate and run the distributor with: `cargo run --features test-branch`

6. Open a browser to localhost:8000 and use developer settings to inspect the console. 

7. Right click on the output and select `Save All messages to File`

8. Give the file a unique name that ends with `.log` and save to the
   `console_logs` directory inside `lox-extensions`. If the directory doesn't
   exist, create it. 

9. Shut down the distributor, clear the database with `rm -rf lox_db/`

10. Repeat steps 5 - 9 for each iteration of the test.

### Run the native-native tests and parse results

1. To generate data for tables 2 and 5, From the `lox-extensions` crate run: `./run_test`. 
The output from the native-native tests run by this command will be automatically parsed into csv format and
appear in the `parsed_results` folder.
   
2.  For the wasm-native results for table 2, following the steps for wasm-native above, the logs will be parsed along with the native-native tests and results will appear in csv format in the `console_logs` folder. 


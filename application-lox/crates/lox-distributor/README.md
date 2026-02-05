# Lox Distributor

The Lox distributor receives resources from [rdsys](https://gitlab.torproject.org/tpo/anti-censorship/rdsys) and writes them to [Lox
BridgeLines](https://git-crysp.uwaterloo.ca/iang/lox/src/master/src/bridge_table.rs#L42). Concurrently, it receives and responds to requests from [Lox clients](../lox-wasm). It saves the [LoxContext](https://gitlab.torproject.org/tpo/anti-censorship/lox-rs/-/blob/main/crates/lox-distributor/src/lox_context.rs) to a database every time the Lox bridgetable is updated and before the distributor is shutdown.


## Configuration

A test `config.json` is included for testing on a local instance of rdsys. There are several configurable
fields in this config file:

### DB Config

The DB config `db` accepts a `db_path` where the Lox distributor will look for or create a new Lox database as follows:

```
"db": {
    "db_path": "path/to/db"
}
```

### Rdsys Config

The rdsys request `rtype` has the following fields:

 `endpoint` the endpoint of the rdsys instance that the distributor will make requests to,

 `name` the type of distributor we are requesting. In most cases this should be `lox`,

 `token` the corresponding Api Token,

 `types` the type of bridges that are being accepted.

 Example configuration:
 ```
     "rtype": {
        "endpoint": "http://127.0.0.1:7100/resources",
        "name": "lox",
        "token": "LoxApiTokenPlaceholder",
        "types": [
            "obfs4",
            "scramblesuit"
        ]
    }
 ```

### Bridge Config

The Bridge config, `bridge_config` has the following fields:

`watched_blockages` lists the regions (as ISO 3166 country codes) that Lox will monitor for listed blockages

`percent_spares` is the percentage of buckets that should be allocated as hot spares (as opposed to open invitation buckets)

Example configuration:
```
    "bridge_config": {
        "watched_blockages": [
            "RU"
        ],
        "percent_spares": 50
    },
```
### Metrics Port

The `metrics_port` field is the port that the prometheus server will run on.

### Command Line Arguments for Advanced Database Config

There are a few configurations for the Lox database that can be passed as arguments at run time since they are not likely to be suitable as persistent configuration options.

Rolling back to a previous version of the database is possible by passing the
`roll_back_date` flag at runtime and providing the date/time as a `%Y-%m-%d_%H:%M:%S` string. This argument should be passed if the `LoxContext` should be rolled back to a previous state due to, for example, a mass blocking event that is likely not due to Lox user behaviour. If the exact roll back date/time is not known, the last db entry within 24 hours from the passed `roll_back_date` will be used or else the program will fail gracefully.


## Distributor Staging Environnment

The lox distributor is currently deployed for testing on `rdsys-frontend-01`.
Client requests can be made to this distributor by following the instructions in the [`lox-wasm` README](../lox-wasm/README.md/#testing)

## Running the Lox Distributor Locally

For testing purposes, you will need a locally running instance of [rdsys](https://gitlab.torproject.org/tpo/anti-censorship/rdsys) as well as a running [Lox client](../lox-wasm/).

### Run rdsys locally

First clone rdsys from [here](https://gitlab.torproject.org/tpo/anti-censorship/rdsys) then follow the instructions in the [README](https://gitlab.torproject.org/tpo/anti-censorship/rdsys/-/blob/main/README.md) to create a locally running rdsys instance with fake bridge descriptors.

### Run Lox Distributor locally

The easiest way to test with rdsys is to adjust the [config.json](config.json) so that the `rtype` reads as follows:
```
    "rtype": {
        "endpoint": "http://127.0.0.1:7100/resources",
        "name": "https",
        "token": "HttpsApiTokenPlaceholder",
        "types": [
            "obfs4",
            "snowflake"
        ]
    }
```

Then simply run `cargo run -- config.json` :)

### Run a Lox client locally

First clone lox-wasm from [here](../lox-wasm). Follow the instructions in the [README](../lox-wasm/README.md) to build and test the Lox client.

# OONI User Auth

Run example:
```bash
cargo run -p ooniauth-core --release --example basic_usage
```

iOS build:
Open `ios/OoniAuthApp.xcodeproj` in Xcode.

Criterion benchmark (same flow):
```bash
cargo bench -p ooniauth-core
```

Extract Criterion means/std devs (ms) for table rows:
```bash
python3 scripts/criterion_extract.py
```

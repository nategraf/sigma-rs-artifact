all: stubs
	maturin build --release

dev: stubs
	maturin develop

dev-release: stubs
	maturin develop --release

stubs:
	cargo run --bin gen_stubs

clean:
	cargo clean

test:
	cargo test

# This rule is supposed to be temporary while we figure out the distribution.
# The ./wheels directory will have pre-compiled wheels for easy download and
# installation.
# ooniprobe will specify this dependency as an url to the file hosted in Github
wheels: all
	cp ../target/wheels/*.whl ./wheels

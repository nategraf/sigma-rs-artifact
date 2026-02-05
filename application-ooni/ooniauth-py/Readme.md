# ooniauth-py

This is the bindings library used to call the anonymous credentials library from Python land

We use this in our backend implement the anonymous credentials protocol in our API

## Requirements

1. [maturin](https://github.com/PyO3/maturin): Is used to build the library itself, it's heavily used to develop this library

## Installation

In order to use [maturin](https://github.com/PyO3/maturin), you need a virtual environment to manage
the resulting Python package during development, see more details 
[here](https://www.maturin.rs/tutorial.html#install-and-configure-maturin-in-a-virtual-environment)

### Testing Installation

If you try to run the tests as you usually would with `cargo test`, you will get linking errors. This 
happens because Maturin provides a build configuration with all the linking flags required to build
the library. However, it does not provide a `maturing test` command that could help you with this.

A possible solution is to manually specify the linking flags to the compiler, but in order to do this 
you will probably need to download the specific Python version (3.10). A good way to do this
is using [Pyenv](https://github.com/pyenv/pyenv):

1. [Install Pyenv](https://github.com/pyenv/pyenv?tab=readme-ov-file#installation)
2. Install Python 3.10.0 with pyenv: `pyenv install 3.10.0`

With the Python version installed, you can create a `.cargo/config.toml` 
with the linking flags. Create the file in `userauth/.cargo/config.toml` 
and fill the following template: 

```toml
[target.'cfg(all())']
rustflags = [
    "-C", "link-arg=-Wl,-rpath,<YOUR PYENV PATH HERE>/.pyenv/versions/3.10.0/lib",
    "-C", "link-arg=-L<YOUR PYENV PATH HERE>/.pyenv/versions/3.10.0/lib",
    "-C", "link-arg=-lpython3.10",
]
```

Example result: 
```toml
[target.'cfg(all())']
rustflags = [
    "-C", "link-arg=-Wl,-rpath,/home/ooni/.pyenv/versions/3.10.0/lib",
    "-C", "link-arg=-L/home/ooni/.pyenv/versions/3.10.0/lib",
    "-C", "link-arg=-lpython3.10",
]
```

**Note**: Make sure to create this file in `userauth/.cargo/config.toml` and not in `userauth/ooniauth-py/.cargo.toml`

## Usage

1. Create a ready-to-use `.whl` to import in python: `make wheels`
  - **Note**: You will find the wheels file in: `/userauth/ooniauth-py/wheels`
2. Build the library and install it in a virtualenv for trying it in Python: `make dev`
  - **Note**: Requires an active virtual environment to install the library
3. Run tests: `make test`

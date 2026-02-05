use ooniauth_py::stub_info;
use pyo3_stub_gen::Result;

fn main() -> Result<()> {
    // `stub_info` is a function defined by `define_stub_info_gatherer!` macro.
    let stub = stub_info()?;
    stub.generate()?;
    Ok(())
}

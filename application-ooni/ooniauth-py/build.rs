use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=PYO3_PYTHON");
    println!("cargo:rerun-if-env-changed=PYTHON_SYS_EXECUTABLE");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "macos" && target_os != "linux" {
        return;
    }

    let flags = python3_config_ldflags();
    if let Some(flags) = flags {
        emit_link_flags(&flags);
    }
}

fn python3_config_ldflags() -> Option<String> {
    run_python3_config(&["--embed", "--ldflags"]).or_else(|| run_python3_config(&["--ldflags"]))
}

fn run_python3_config(args: &[&str]) -> Option<String> {
    let output = Command::new("python3-config").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn emit_link_flags(flags: &str) {
    let mut iter = flags.split_whitespace().peekable();
    while let Some(flag) = iter.next() {
        if let Some(path) = flag.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={path}");
        } else if let Some(lib) = flag.strip_prefix("-l") {
            println!("cargo:rustc-link-lib={lib}");
        } else if flag == "-framework" {
            if let Some(name) = iter.next() {
                println!("cargo:rustc-link-lib=framework={name}");
            }
        }
    }
}

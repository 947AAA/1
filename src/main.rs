mod bridge;

use clap::Parser;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "patch_kernel_root", version, about = "SKRoot ARM64 Linux Kernel Root Patcher for Android")]
struct Cli {
    #[arg(short = 'i', long = "input", required = true)]
    input: PathBuf,

    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,

    #[arg(short = 'k', long = "key")]
    key: Option<String>,

    #[arg(long = "auto-key", default_value_t = false)]
    auto_key: bool,
}

fn main() {
    let cli = Cli::parse();

    if !cli.input.exists() {
        eprintln!("[ERROR] Input file not found: {}", cli.input.display());
        process::exit(1);
    }

    let output = cli.output.unwrap_or_else(|| cli.input.clone());

    let root_key = if cli.auto_key {
        None
    } else {
        cli.key.as_deref()
    };

    match bridge::patch_kernel_bin(&cli.input, &output, root_key) {
        Ok(key) => {
            println!("[SUCCESS] Kernel patched successfully");
            println!("[KEY] Root key: {}", key);
        }
        Err(e) => {
            eprintln!("[ERROR] {}", e);
            process::exit(1);
        }
    }
}

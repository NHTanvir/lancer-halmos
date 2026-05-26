//! lancer-halmos
//! Rust clone of halmos. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-halmos", version, about = "Rust clone of halmos")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-halmos - scaffold ready. Implement per plan.md.");
    Ok(())
}

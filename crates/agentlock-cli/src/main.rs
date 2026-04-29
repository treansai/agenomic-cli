fn main() {
    if let Err(error) = agentlock_cli::run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

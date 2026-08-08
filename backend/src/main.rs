#![forbid(unsafe_code)]
//! RoleBlank OS backend entry point.
//!
//! Subcommands are explicit and separate. In particular `migrate` is **not**
//! folded into `serve`: implicit migration on startup races every replica of a
//! rolling deploy against the same schema change, and turns a bad migration into
//! an outage rather than a failed, deliberate step (brief §8).

use std::process::ExitCode;

use roleblank_backend::cli;

#[tokio::main]
async fn main() -> ExitCode {
    let command = match cli::Command::from_args(std::env::args().skip(1)) {
        Ok(c) => c,
        Err(message) => {
            eprintln!("{message}\n{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };

    match cli::run(command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Plain text on stderr: at this point the logging subscriber may not be
            // initialised, and an operator reading a container log needs the reason
            // immediately rather than after configuring a log level.
            eprintln!("\nERROR: {message}\n");
            ExitCode::FAILURE
        }
    }
}

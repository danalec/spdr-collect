//! `spdr-collect` — the intake tool for the `spdr` project.
//!
//! A contributor has a DDR5 module and wants its SPD image to be part of the
//! project's fixture corpus. The hard parts are not decoding, which `spdr`
//! already does: they are reading whatever format the dump arrived in, and
//! removing the fields that identify the module without touching the bytes the
//! CRC protects.
//!
//! This tool does both, and prints the provenance record the project's
//! `docs/validated-against.md` asks for.
//!
//! ```text
//! spdr-collect check    dump.bin
//! spdr-collect sanitize dump.bin -o fixtures/my-module.spd
//! ```

mod ingest;
mod report;
mod sanitize;
mod submit;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use ingest::Ingested;
use report::{EXIT_OK, Report};
use sanitize::Redaction;

/// The run could not happen: the file was unreadable, or the format was not
/// one this tool reads.
const EXIT_CANNOT_RUN: u8 = 2;

#[derive(Parser)]
#[command(
    name = "spdr-collect",
    version,
    about = "Intake tool for DDR5 SPD dumps: ingest, redact, validate, and package a fixture",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report what a dump contains, without writing anything.
    Check(CheckArgs),
    /// Redact the identifying fields, validate, and write the fixture.
    Sanitize(SanitizeArgs),
    /// Redact, validate, and send the fixture to the upstream repository.
    Submit(SubmitArgs),
}

#[derive(clap::Args)]
struct CheckArgs {
    /// The dump to read.
    file: PathBuf,
    /// Print the report as JSON.
    #[arg(long)]
    json: bool,
    /// Read a hex dump with its 16-bit groups byte-swapped, which is what
    /// plain `hexdump` writes on a little-endian host.
    #[arg(long)]
    swap_words: bool,
    /// Read the file as a raw binary image, whatever it looks like.
    #[arg(long)]
    raw: bool,
}

#[derive(clap::Args)]
struct SanitizeArgs {
    /// The dump to read.
    file: PathBuf,
    /// Where to write the sanitised fixture. Without it, nothing is written
    /// and the report is the whole output.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// What to redact. The serial number is the unique device identifier; the
    /// part number is public product data and is kept by default.
    #[arg(long, value_enum, default_value_t = Redaction::Serial)]
    redact: Redaction,
    /// Where to write the report. Without it, the report goes to stdout.
    #[arg(long)]
    report: Option<PathBuf>,
    /// Print the report as JSON.
    #[arg(long)]
    json: bool,
    /// Read a hex dump with its 16-bit groups byte-swapped, which is what
    /// plain `hexdump` writes on a little-endian host.
    #[arg(long)]
    swap_words: bool,
    /// Read the file as a raw binary image, whatever it looks like.
    #[arg(long)]
    raw: bool,
}

#[derive(clap::Args)]
struct SubmitArgs {
    /// The dump to read.
    file: PathBuf,
    /// The repository to send the fixture to.
    #[arg(long, default_value = submit::DEFAULT_TARGET)]
    target: String,
    /// Where to send it. A pull request is the only way a binary fixture can
    /// land; an issue carries the provenance and the file goes in by hand.
    #[arg(long = "as", value_enum, default_value = "pr")]
    channel: submit::Channel,
    /// The fixture file name. Without it, one is derived from the module.
    #[arg(long)]
    name: Option<String>,
    /// Do not add an entry to `docs/validated-against.md`; the provenance goes
    /// in the pull request body instead.
    #[arg(long)]
    no_docs: bool,
    /// What to redact. The serial number is the unique device identifier; the
    /// part number is public product data and is kept by default.
    #[arg(long, value_enum, default_value_t = Redaction::Serial)]
    redact: Redaction,
    /// Print what would be sent, and send nothing.
    #[arg(long)]
    dry_run: bool,
    /// Read a hex dump with its 16-bit groups byte-swapped, which is what
    /// plain `hexdump` writes on a little-endian host.
    #[arg(long)]
    swap_words: bool,
    /// Read the file as a raw binary image, whatever it looks like.
    #[arg(long)]
    raw: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = match &cli.command {
        Command::Check(args) => run_check(args),
        Command::Sanitize(args) => run_sanitize(args),
        Command::Submit(args) => run_submit(args),
    };
    ExitCode::from(code)
}

/// Validate a dump and report what it holds.
fn run_check(args: &CheckArgs) -> u8 {
    let Some(ingested) = read_input(&args.file, args.raw, args.swap_words) else {
        return EXIT_CANNOT_RUN;
    };
    let report = report::build(
        &args.file.display().to_string(),
        &ingested,
        &report::sha256_hex(&ingested.bytes),
        None,
        Redaction::None,
    );
    emit(&report, args.json, None);
    report.exit_code()
}

/// Redact, validate, and write the fixture.
fn run_sanitize(args: &SanitizeArgs) -> u8 {
    let Some(mut ingested) = read_input(&args.file, args.raw, args.swap_words) else {
        return EXIT_CANNOT_RUN;
    };

    // The hash of the file the contributor actually had, before the redaction.
    let input_sha256 = report::sha256_hex(&ingested.bytes);

    sanitize::apply(&mut ingested.bytes, args.redact);
    let mut report = report::build(
        &args.file.display().to_string(),
        &ingested,
        &input_sha256,
        None,
        args.redact,
    );

    let suggested = report::suggested_name(&report);
    match &args.output {
        Some(path) => {
            if let Err(err) = std::fs::write(path, &ingested.bytes) {
                eprintln!("spdr-collect: cannot write {}: {err}", path.display());
                return EXIT_CANNOT_RUN;
            }
            report.output = Some(report::OutputInfo {
                path: path.display().to_string(),
                bytes: ingested.bytes.len(),
                sha256: report::sha256_hex(&ingested.bytes),
                suggested_name: suggested,
            });
        }
        None => {
            report.notes.push(format!(
                "nothing was written; a fixture name would be `{suggested}`"
            ));
        }
    }

    emit(&report, args.json, args.report.as_deref());
    report.exit_code()
}

/// Redact, validate, and send the fixture to the upstream repository.
fn run_submit(args: &SubmitArgs) -> u8 {
    let Some(mut ingested) = read_input(&args.file, args.raw, args.swap_words) else {
        return EXIT_CANNOT_RUN;
    };
    let input_sha256 = report::sha256_hex(&ingested.bytes);

    // The redaction map is checked against the decoder before anything is
    // written, so a drift is caught before a fixture is pushed.
    if let Err(drift) = sanitize::check_offsets(&ingested.bytes) {
        eprintln!("spdr-collect: {drift}");
        return EXIT_CANNOT_RUN;
    }

    sanitize::apply(&mut ingested.bytes, args.redact);
    let mut report = report::build(
        &args.file.display().to_string(),
        &ingested,
        &input_sha256,
        None,
        args.redact,
    );

    let fixture_name = args
        .name
        .clone()
        .unwrap_or_else(|| report::suggested_name(&report));
    let fixture_path = format!("spdr/tests/fixtures/{fixture_name}");
    report.output = Some(report::OutputInfo {
        path: fixture_path.clone(),
        bytes: ingested.bytes.len(),
        sha256: report::sha256_hex(&ingested.bytes),
        suggested_name: fixture_name.clone(),
    });

    let submission = submit::Submission {
        target: &args.target,
        channel: args.channel,
        fixture_name: fixture_name.clone(),
        fixture: &ingested.bytes,
        report: &report,
        with_docs: !args.no_docs,
    };

    if args.dry_run {
        println!("# Dry run: nothing was sent.\n");
        println!(
            "## Target\n\n- repository · `{}`\n- channel · `{:?}`\n- fixture · `{fixture_path}`\n- branch · `{}`\n",
            submission.target,
            submission.channel,
            submit::branch_name(&fixture_name),
        );
        println!(
            "## What would be sent\n\n{}",
            report::render_markdown(&report)
        );
        return EXIT_OK;
    }

    match submit::send(&submission) {
        Ok(outcome) => {
            println!("Sent: {outcome_url}", outcome_url = outcome.url);
            if let Some(branch) = &outcome.branch {
                println!("The branch is `{branch}`");
            }
            if let Some(checkout) = &outcome.checkout {
                println!("It is checked out at {}", checkout.display());
            }
            EXIT_OK
        }
        Err(err) => {
            eprintln!("spdr-collect: {err}");
            eprintln!();
            eprintln!("To send it by hand:");
            eprint!(
                "{}",
                submit::manual_steps(
                    &args.target,
                    &fixture_name,
                    &submit::branch_name(&fixture_name),
                )
            );
            EXIT_CANNOT_RUN
        }
    }
}

/// Read the input file into SPD bytes.
fn read_input(path: &Path, raw: bool, swap: bool) -> Option<Ingested> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("spdr-collect: cannot read {}: {err}", path.display());
            return None;
        }
    };
    if raw {
        return Some(ingest::ingest_raw(&bytes));
    }
    match ingest::ingest(&bytes, swap) {
        Ok(ingested) => Some(ingested),
        Err(err) => {
            eprintln!("spdr-collect: cannot read {}: {err}", path.display());
            eprintln!("spdr-collect: hint: pass --raw to read the file as a binary image");
            None
        }
    }
}

/// Print the report, or write it to a file.
fn emit(report: &Report, json: bool, to: Option<&Path>) {
    let text = if json {
        match serde_json::to_string_pretty(report) {
            Ok(text) => text,
            Err(err) => format!("{{\"error\":\"{err}\"}}"),
        }
    } else {
        report::render_markdown(report)
    };

    match to {
        Some(path) => {
            if let Err(err) = std::fs::write(path, text) {
                eprintln!("spdr-collect: cannot write {}: {err}", path.display());
            }
        }
        None => println!("{text}"),
    }
}

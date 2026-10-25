# AGENTS.md

Intake tool for the [`spdr`](https://github.com/The-Open-Memory-Initiative-OMI/spdr) project: it ingests a DDR5 SPD dump in whatever format the contributor has, redacts the fields that identify their module, validates the result, and prints the provenance record the project asks for.

## Setup commands

- Install deps: `cargo build` (the `spdr` dependency comes from crates.io)
- Run the CLI: `cargo run -- check <spd-file>` · `cargo run -- sanitize <spd-file> -o <out>`
- Build:        `cargo build --release`
- Test:         `cargo test --all-targets`
- Lint:         `cargo clippy --all-targets -- -D warnings`
- Format check: `cargo fmt --check` (fix with `cargo fmt`)

## Project layout

- `src/ingest.rs` · reading a raw image, a hex dump (`hexdump -C`, `xxd`, `od`, `i2cdump`), or a bare hex string
- `src/sanitize.rs` · the redaction map and the placeholders
- `src/report.rs` · the provenance report, markdown and JSON
- `src/main.rs` · the two subcommands and the exit-code contract
- `tests/cli.rs` · integration tests against the fixture in `tests/fixtures/`
- `.github/workflows/ci.yml` · fmt → clippy → test

## The invariant that must not break

**Every identifying field lives outside the range the base configuration CRC covers.** The CRC covers bytes `0..=509`; the manufacturing information block, which holds the serial number (517..=520) and the part number (521..=550), starts at byte 512. Redacting therefore cannot disturb the CRC, and a sanitised dump stays a faithful image of the module instead of a reconstruction.

If a field is ever added to the redaction map, check that it is still outside `0..=509`. A field inside that range would need the CRC recomputed, which would break the guarantee the whole tool rests on.

## Code style

- Rust 2024 edition, MSRV 1.85; `cargo fmt` before committing
- The workspace lints in `Cargo.toml` deny the same curated `clippy::pedantic` set the `spdr` project denies, plus `unsafe_code = "forbid"`. CI treats every warning as an error.
- No `unsafe`, and no panicking path: the input is untrusted bytes, and the tool reports what it finds rather than failing on it.

## Claims & documentation

- Every number the tool prints must be traceable: the SHA-256 of a source file, the CRC computed and stored, the byte counts. Do not print a number whose origin is not in the report.
- A CRC mismatch is reported, never blocking. The exit code follows the `spdr` CLI contract: `0` when every section decoded, `1` when one did not, `2` when the run could not happen.

## Tests

- The tests run against the fixture in `tests/fixtures/`, a byte-identical copy of the upstream project's fixture. Its SHA-256 is asserted against the value the upstream project already documents, which is the independent check that the provenance hash is right.
- A test that changes the tool's behaviour should fail before the change and pass after it.

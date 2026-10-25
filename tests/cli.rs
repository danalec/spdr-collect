//! Integration tests for the `spdr-collect` binary.
//!
//! The tests run against the real fixture the `spdr` project keeps, so they
//! check the tool against an image whose CRC and contents are already
//! documented upstream. They skip, rather than fail, when that fixture is not
//! next to this checkout.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

const BINARY: &str = env!("CARGO_BIN_EXE_spdr-collect");

/// The fixture the `spdr` project validates against.
fn fixture() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("spdr")
        .join("spdr")
        .join("tests")
        .join("fixtures")
        .join("teamgroup-ud5-6000_0104eef6.spd");
    path.exists().then_some(path)
}

/// Run the tool.
fn run(args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .output()
        .expect("the spdr-collect binary runs")
}

/// The stdout of a run, as a string.
fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The SHA-256 of a file, lowercase hex.
fn sha256_file(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("the file reads");
    let mut out = String::new();
    for byte in Sha256::digest(&bytes) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[test]
fn check_reports_a_matching_crc_and_a_clean_lint() {
    let Some(fixture) = fixture() else {
        return;
    };
    let output = run(&["check", fixture.to_str().expect("a path")]);
    let text = stdout(&output);

    assert_eq!(output.status.code(), Some(0), "the report was: {text}");
    assert!(text.contains("computed `0x8021`"), "{text}");
    assert!(text.contains("match"), "{text}");
    assert!(text.contains("Team Group Inc."), "{text}");
    assert!(text.contains("UD5-6000"), "{text}");
    assert!(text.contains("no findings"), "{text}");
}

#[test]
fn sanitize_touches_the_serial_and_nothing_else() {
    let Some(fixture) = fixture() else {
        return;
    };
    let out = fixture.with_file_name("sanitised.spd");
    let output = run(&[
        "sanitize",
        fixture.to_str().expect("a path"),
        "-o",
        out.to_str().expect("a path"),
    ]);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "the report was: {text}");

    let original = std::fs::read(&fixture).expect("the fixture reads");
    let sanitised = std::fs::read(&out).expect("the fixture was written");
    assert_eq!(original.len(), sanitised.len());

    let changed: Vec<usize> = original
        .iter()
        .zip(&sanitised)
        .enumerate()
        .filter(|(_, (before, after))| before != after)
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        changed,
        vec![517, 518, 519, 520],
        "only the four serial bytes may change"
    );
    assert_eq!(&sanitised[517..=520], &[0x99, 0x99, 0x99, 0x99]);

    let _ = std::fs::remove_file(&out);
}

#[test]
fn sanitize_leaves_the_crc_intact() {
    let Some(fixture) = fixture() else {
        return;
    };
    let out = fixture.with_file_name("sanitised-crc.spd");
    let output = run(&[
        "sanitize",
        fixture.to_str().expect("a path"),
        "-o",
        out.to_str().expect("a path"),
    ]);
    let text = stdout(&output);

    assert!(text.contains("computed `0x8021`"), "{text}");
    assert!(text.contains("match"), "the CRC must survive: {text}");
    assert!(text.contains("serial `99999999`"), "{text}");

    let _ = std::fs::remove_file(&out);
}

#[test]
fn the_source_hash_points_at_the_original_and_the_fixture_hash_at_the_output() {
    let Some(fixture) = fixture() else {
        return;
    };
    let out = fixture.with_file_name("sanitised-hash.spd");
    let output = run(&[
        "sanitize",
        fixture.to_str().expect("a path"),
        "-o",
        out.to_str().expect("a path"),
    ]);
    let text = stdout(&output);

    let source_hash = sha256_file(&fixture);
    let output_hash = sha256_file(&out);
    assert!(text.contains(&source_hash), "{text}");
    assert!(text.contains(&output_hash), "{text}");
    assert_ne!(
        source_hash, output_hash,
        "the redaction must change the file"
    );

    let _ = std::fs::remove_file(&out);
}

#[test]
fn a_hex_dump_ingests_to_the_same_bytes() {
    let Some(fixture) = fixture() else {
        return;
    };
    let bytes = std::fs::read(&fixture).expect("the fixture reads");
    let dump = fixture.with_file_name("dump-xxd.txt");

    let mut text = String::new();
    for (index, chunk) in bytes.chunks(16).enumerate() {
        let groups: Vec<String> = chunk
            .chunks(2)
            .map(|pair| {
                pair.iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
            .collect();
        text.push_str(&format!("{:08x}: {}\n", index * 16, groups.join(" ")));
    }
    std::fs::write(&dump, text).expect("the dump writes");

    let output = run(&["check", dump.to_str().expect("a path")]);
    let report = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{report}");
    assert!(report.contains("hex dump"), "{report}");
    assert!(report.contains("computed `0x8021`"), "{report}");
    assert!(report.contains("match"), "{report}");

    let _ = std::fs::remove_file(&dump);
}

#[test]
fn a_plain_hex_string_ingests_to_the_same_bytes() {
    let Some(fixture) = fixture() else {
        return;
    };
    let bytes = std::fs::read(&fixture).expect("the fixture reads");
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let dump = fixture.with_file_name("dump-plain.hex");
    std::fs::write(&dump, hex).expect("the dump writes");

    let output = run(&["check", dump.to_str().expect("a path")]);
    let report = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{report}");
    assert!(report.contains("plain hex"), "{report}");
    assert!(report.contains("computed `0x8021`"), "{report}");

    let _ = std::fs::remove_file(&dump);
}

#[test]
fn a_short_image_reports_the_sections_it_could_not_decode() {
    let Some(fixture) = fixture() else {
        return;
    };
    let bytes = std::fs::read(&fixture).expect("the fixture reads");
    let short = fixture.with_file_name("short.spd");
    std::fs::write(&short, &bytes[..100]).expect("the image writes");

    let output = run(&["check", short.to_str().expect("a path")]);
    let report = stdout(&output);
    assert_eq!(output.status.code(), Some(1), "{report}");
    assert!(report.contains("Not decoded"), "{report}");
    assert!(report.contains("100 bytes"), "{report}");

    let _ = std::fs::remove_file(&short);
}

#[test]
fn a_file_that_is_not_there_cannot_be_run() {
    let output = run(&["check", "no-such-file.spd"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot read"),
        "the failure is reported on stderr"
    );
}

#[test]
fn text_that_is_not_hex_cannot_be_run() {
    let path = std::env::temp_dir().join("spdr-collect-not-hex.txt");
    std::fs::write(&path, "this is a note to self, not a dump\n").expect("the file writes");

    let output = run(&["check", path.to_str().expect("a path")]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--raw"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_json_report_carries_the_same_facts() {
    let Some(fixture) = fixture() else {
        return;
    };
    let output = run(&["check", "--json", fixture.to_str().expect("a path")]);
    let report = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{report}");
    assert!(report.contains("\"computed\": 32801"), "{report}");
    assert!(report.contains("\"matches\": true"), "{report}");
    assert!(report.contains("\"module_type\": \"UDIMM\""), "{report}");
}

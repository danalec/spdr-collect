//! The provenance report a sanitised dump is submitted with.
//!
//! The report is the part a contributor pastes into `docs/validated-against.md`
//! in the `spdr` project: what the file was, where it came from, what was
//! redacted, whether the CRC still matches, and what the image decodes to.

use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest, Sha256};
use spdr::{
    CrcStatus, DecodeError, Finding, Severity, decode_identity_and_base, decode_manufacturing,
    decode_module_specific, decode_timings, decode_vendor_profiles, lint, verify_base_crc,
};

use crate::ingest::Ingested;
use crate::sanitize::Redaction;

/// Every section decoded.
pub const EXIT_OK: u8 = 0;
/// At least one section failed to decode.
pub const EXIT_DECODE_ERROR: u8 = 1;

/// The SHA-256 of a byte string, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Where the bytes came from.
#[derive(Debug, Serialize)]
pub struct InputInfo {
    /// The path the contributor pointed at.
    pub path: String,
    /// The format it was recognised as.
    pub format: String,
    /// Its size in bytes.
    pub bytes: usize,
    /// The SHA-256 of the original bytes, before any redaction.
    pub sha256: String,
    /// The byte order used inside hex-dump groups, when the input was one.
    pub word_order: Option<String>,
}

/// What was written.
#[derive(Debug, Serialize)]
pub struct OutputInfo {
    /// The path written to.
    pub path: String,
    /// Its size in bytes.
    pub bytes: usize,
    /// The SHA-256 of the written bytes.
    pub sha256: String,
    /// A fixture file name that follows the project's convention.
    pub suggested_name: String,
}

/// What was removed.
#[derive(Debug, Serialize)]
pub struct RedactionInfo {
    /// The level that was applied, as a stable token.
    pub level: String,
    /// The level that was applied, in words.
    pub description: String,
    /// The fields it removed.
    pub fields: Vec<String>,
}

/// The base configuration CRC.
#[derive(Debug, Serialize)]
pub struct CrcInfo {
    /// The CRC computed over bytes 0..=509.
    pub computed: u16,
    /// The CRC stored in the image.
    pub stored: u16,
    /// Whether the two agree.
    pub matches: bool,
}

/// One decoded section.
#[derive(Debug, Serialize)]
pub struct SectionInfo {
    /// The section name.
    pub name: String,
    /// Whether it decoded.
    pub decoded: bool,
    /// The error, when it did not.
    pub detail: Option<String>,
}

/// The identity and base configuration.
#[derive(Debug, Serialize)]
pub struct IdentityInfo {
    /// The base module type.
    pub module_type: String,
    /// The DRAM device type.
    pub device_type: String,
    /// The SPD revision.
    pub spd_revision: String,
    /// The SDRAM density per die, in gigabits.
    pub density_per_die_gb: u16,
    /// The SDRAM I/O device width, in DQ pins.
    pub io_width_bits: u16,
    /// The bank groups per die.
    pub bank_groups: u8,
    /// The banks per bank group.
    pub banks_per_bank_group: u8,
    /// The package construction.
    pub package_type: String,
    /// The dies in the package.
    pub die_count: u8,
    /// The package ranks per channel.
    pub ranks_per_channel: u8,
    /// The channels per DIMM.
    pub channels_per_dimm: u8,
    /// The primary bus width per channel, in bits.
    pub primary_bus_width_bits: u16,
    /// The base data rate from the JEDEC timings, in MT/s.
    pub base_data_rate_mt_s: Option<u32>,
}

/// The manufacturing information block.
#[derive(Debug, Serialize)]
pub struct ManufacturingInfo {
    /// The module manufacturer name, when the JEP-106 code resolves.
    pub manufacturer: Option<String>,
    /// The JEP-106 bank.
    pub manufacturer_bank: u8,
    /// The JEP-106 manufacturer code.
    pub manufacturer_code: u8,
    /// The manufacturer-specific location code.
    pub manufacturing_location: u8,
    /// The manufacturing year.
    pub manufacturing_year: u16,
    /// The manufacturing week.
    pub manufacturing_week: u8,
    /// The module serial number, as it reads after redaction.
    pub serial_number: String,
    /// The module part number, as it reads after redaction.
    pub part_number: String,
    /// The revision code.
    pub revision_code: u8,
    /// The DRAM manufacturer name, when the JEP-106 code resolves.
    pub dram_manufacturer: Option<String>,
    /// The DRAM stepping.
    pub dram_stepping: u8,
}

/// One lint finding.
#[derive(Debug, Clone, Serialize)]
pub struct FindingInfo {
    /// The severity.
    pub severity: String,
    /// The stable rule code.
    pub code: String,
    /// The message.
    pub message: String,
}

/// The lint result.
#[derive(Debug, Serialize)]
pub struct LintInfo {
    /// The number of error findings.
    pub errors: usize,
    /// The number of warning findings.
    pub warnings: usize,
    /// The number of informational findings.
    pub infos: usize,
    /// Every finding, in the order the linter produced them.
    pub findings: Vec<FindingInfo>,
}

/// The whole report.
#[derive(Debug, Serialize)]
pub struct Report {
    /// Where the bytes came from.
    pub input: InputInfo,
    /// What was written, when anything was.
    pub output: Option<OutputInfo>,
    /// What was removed.
    pub redaction: RedactionInfo,
    /// The base configuration CRC, when the image was long enough to hold it.
    pub crc: Option<CrcInfo>,
    /// Every section the library decodes.
    pub sections: Vec<SectionInfo>,
    /// The identity and base configuration.
    pub identity: Option<IdentityInfo>,
    /// The manufacturing information block.
    pub manufacturing: Option<ManufacturingInfo>,
    /// The lint result.
    pub lint: LintInfo,
    /// Anything the contributor should look at before submitting.
    pub notes: Vec<String>,
}

impl Report {
    /// Whether every section decoded. A CRC mismatch is reported, never
    /// blocking, so it does not count as a failed section.
    pub fn all_decoded(&self) -> bool {
        self.sections.iter().all(|section| section.decoded)
    }

    /// The exit code this report implies, following the `spdr` CLI contract.
    pub fn exit_code(&self) -> u8 {
        if self.all_decoded() {
            EXIT_OK
        } else {
            EXIT_DECODE_ERROR
        }
    }
}

/// Build the report for an image.
///
/// `input_sha256` is the SHA-256 of the bytes as they were read, before any
/// redaction. It is passed in rather than computed here because the caller
/// sanitises the image in place, and the source hash has to keep pointing at
/// the file the contributor actually had.
pub fn build(
    path: &str,
    ingested: &Ingested,
    input_sha256: &str,
    output: Option<OutputInfo>,
    redaction: Redaction,
) -> Report {
    let bytes = &ingested.bytes;
    let notes = Vec::new();

    // Each decoder runs once; the results feed both the section list and the
    // summaries below.
    let identity_result = decode_identity_and_base(bytes);
    let timings_result = decode_timings(bytes);
    let module_result = decode_module_specific(bytes);
    let manufacturing_result = decode_manufacturing(bytes);
    let vendor_result = decode_vendor_profiles(bytes);

    let crc = match verify_base_crc(bytes) {
        Ok(status) => Some(crc_info(status)),
        Err(_) => None,
    };

    let sections = vec![
        section("identity and base configuration", &identity_result),
        section("base JEDEC timings", &timings_result),
        section("module-specific block", &module_result),
        section("manufacturing information block", &manufacturing_result),
        section("vendor overclock profiles", &vendor_result),
    ];

    let identity = identity_result.ok().map(|identity| {
        let rate = timings_result
            .ok()
            .map(|timings| timings.base_data_rate_mt_s());
        IdentityInfo {
            module_type: identity.module_type.to_string(),
            device_type: identity.device_type.to_string(),
            spd_revision: identity.spd_revision.to_string(),
            density_per_die_gb: identity.density_per_die.gigabits(),
            io_width_bits: identity.io_width.bits(),
            bank_groups: identity.bank_groups.count(),
            banks_per_bank_group: identity.banks_per_bank_group.count(),
            package_type: identity.package_type.to_string(),
            die_count: identity.die_count,
            ranks_per_channel: identity.package_ranks_per_channel,
            channels_per_dimm: identity.channels_per_dimm,
            primary_bus_width_bits: identity.primary_bus_width_bits,
            base_data_rate_mt_s: rate,
        }
    });

    let manufacturing = manufacturing_result.ok().map(|info| ManufacturingInfo {
        manufacturer: info.module_manufacturer.name.map(str::to_owned),
        manufacturer_bank: info.module_manufacturer.bank,
        manufacturer_code: info.module_manufacturer.code,
        manufacturing_location: info.manufacturing_location,
        manufacturing_year: info.manufacturing_date.year,
        manufacturing_week: info.manufacturing_date.week,
        serial_number: info.serial_number.to_string(),
        part_number: info.part_number.to_owned(),
        revision_code: info.revision_code,
        dram_manufacturer: info.dram_manufacturer.name.map(str::to_owned),
        dram_stepping: info.dram_stepping,
    });

    let mut findings = Vec::new();
    lint(bytes, &mut |finding: Finding| {
        findings.push(finding_info(&finding));
    });
    let lint = lint_info(&findings);

    let mut notes = notes;
    if bytes.len() != 1024 {
        notes.push(format!(
            "the image is {} bytes, not the 1024 a DDR5 SPD holds; the sections past the end did not decode",
            bytes.len()
        ));
    }
    if let Some(crc) = &crc
        && !crc.matches
    {
        notes.push(format!(
            "the base configuration CRC does not match: computed 0x{:04X}, stored 0x{:04X}. The image is reported, not rejected, but a mismatched CRC is usually a truncated or mis-read dump",
            crc.computed, crc.stored
        ));
    }
    if redaction == Redaction::None {
        notes.push(
            "nothing was redacted: the serial number in this file identifies the module it came from"
                .to_owned(),
        );
    }

    Report {
        input: InputInfo {
            path: path.to_owned(),
            format: ingested.format.to_string(),
            bytes: ingested.bytes.len(),
            sha256: input_sha256.to_owned(),
            word_order: ingested.word_order.map(|order| format!("{order:?}")),
        },
        output,
        redaction: RedactionInfo {
            level: format!("{redaction:?}"),
            description: redaction.describe().to_owned(),
            fields: crate::sanitize::redacted_ranges(redaction)
                .into_iter()
                .map(str::to_owned)
                .collect(),
        },
        crc,
        sections,
        identity,
        manufacturing,
        lint,
        notes,
    }
}

/// Turn a CRC status into the report shape.
fn crc_info(status: CrcStatus) -> CrcInfo {
    CrcInfo {
        computed: status.computed,
        stored: status.stored,
        matches: status.matches,
    }
}

/// Turn a decode result into the report shape.
fn section<T>(name: &str, result: &Result<T, DecodeError>) -> SectionInfo {
    match result {
        Ok(_) => SectionInfo {
            name: name.to_owned(),
            decoded: true,
            detail: None,
        },
        Err(err) => SectionInfo {
            name: name.to_owned(),
            decoded: false,
            detail: Some(err.to_string()),
        },
    }
}

/// Turn a finding into the report shape.
fn finding_info(finding: &Finding) -> FindingInfo {
    FindingInfo {
        severity: match finding.severity() {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
        .to_owned(),
        code: finding.code().to_owned(),
        message: finding.to_string(),
    }
}

/// Count the findings by severity.
fn lint_info(findings: &[FindingInfo]) -> LintInfo {
    let mut errors = 0;
    let mut warnings = 0;
    let mut infos = 0;
    for finding in findings {
        match finding.severity.as_str() {
            "error" => errors += 1,
            "warning" => warnings += 1,
            _ => infos += 1,
        }
    }
    LintInfo {
        errors,
        warnings,
        infos,
        findings: findings.to_vec(),
    }
}

/// A fixture file name that follows the project's convention.
pub fn suggested_name(report: &Report) -> String {
    let manufacturer = report
        .manufacturing
        .as_ref()
        .and_then(|info| info.manufacturer.clone())
        .unwrap_or_else(|| "unknown-vendor".to_owned());
    let part = report
        .manufacturing
        .as_ref()
        .map(|info| info.part_number.clone())
        .unwrap_or_default();
    let serial = report
        .manufacturing
        .as_ref()
        .map(|info| info.serial_number.clone())
        .unwrap_or_default();

    let mut stem = slug(&manufacturer);
    if !part.is_empty() {
        stem.push('-');
        stem.push_str(&slug(&part));
    }
    if !serial.is_empty() {
        stem.push('_');
        stem.push_str(&serial);
    }
    format!("{stem}.spd")
}

/// Lowercase a string and reduce it to the characters a file name can carry.
fn slug(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last_was_dash = false;
    for character in text.chars() {
        if character.is_ascii_alphanumeric() {
            out.push(character.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash && !out.is_empty() {
            out.push('-');
            last_was_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

/// Render the report as markdown, ready to paste into the project's notes.
pub fn render_markdown(report: &Report) -> String {
    let mut out = String::new();

    let heading = report
        .identity
        .as_ref()
        .map(|identity| identity.module_type.clone())
        .unwrap_or_else(|| "undecoded".to_owned());
    let vendor = report
        .manufacturing
        .as_ref()
        .and_then(|info| info.manufacturer.clone())
        .unwrap_or_else(|| "Unknown vendor".to_owned());
    let part = report
        .manufacturing
        .as_ref()
        .map(|info| info.part_number.clone())
        .filter(|part| !part.is_empty())
        .unwrap_or_else(|| "no part number".to_owned());
    let _ = writeln!(out, "### {vendor} {part} · {heading}");
    let _ = writeln!(out);

    if let Some(output) = &report.output {
        let _ = writeln!(
            out,
            "- **Fixture** · `{}` · {} bytes · sha256 `{}`",
            output.path, output.bytes, output.sha256
        );
    }
    let _ = writeln!(
        out,
        "- **Source** · `{}` · {} · {} bytes · sha256 `{}`",
        report.input.path, report.input.format, report.input.bytes, report.input.sha256
    );
    let _ = writeln!(out, "- **Sanitised** · {}", report.redaction.description);

    match &report.crc {
        Some(crc) => {
            let _ = writeln!(
                out,
                "- **Base CRC** · computed `0x{:04X}` · stored `0x{:04X}` · {}",
                crc.computed,
                crc.stored,
                if crc.matches { "match" } else { "MISMATCH" }
            );
        }
        None => {
            let _ = writeln!(
                out,
                "- **Base CRC** · not available: the image is too short"
            );
        }
    }

    let decoded: Vec<&str> = report
        .sections
        .iter()
        .filter(|section| section.decoded)
        .map(|section| section.name.as_str())
        .collect();
    let failed: Vec<&str> = report
        .sections
        .iter()
        .filter(|section| !section.decoded)
        .map(|section| section.name.as_str())
        .collect();
    if failed.is_empty() {
        let _ = writeln!(out, "- **Decoded** · {}", decoded.join(", "));
    } else {
        let _ = writeln!(out, "- **Decoded** · {}", decoded.join(", "));
        let _ = writeln!(out, "- **Not decoded** · {}", failed.join(", "));
    }

    if let Some(identity) = &report.identity {
        let rate = match identity.base_data_rate_mt_s {
            Some(rate) => format!(" · {rate} MT/s base"),
            None => String::new(),
        };
        let _ = writeln!(
            out,
            "- **Module** · {} · {} · {} Gb per die · x{} · {} bank groups x {} banks · {} die(s) · {} rank(s) per channel · {} channel(s) · {}-bit bus{}",
            identity.module_type,
            identity.device_type,
            identity.density_per_die_gb,
            identity.io_width_bits,
            identity.bank_groups,
            identity.banks_per_bank_group,
            identity.die_count,
            identity.ranks_per_channel,
            identity.channels_per_dimm,
            identity.primary_bus_width_bits,
            rate
        );
    }

    if let Some(info) = &report.manufacturing {
        let vendor = info.manufacturer.clone().unwrap_or_else(|| {
            format!(
                "unknown (bank {}, code {})",
                info.manufacturer_bank, info.manufacturer_code
            )
        });
        let _ = writeln!(
            out,
            "- **Manufacturer** · {vendor} · {}-W{:02} · location 0x{:02X}",
            info.manufacturing_year, info.manufacturing_week, info.manufacturing_location
        );
        let _ = writeln!(
            out,
            "- **Part number** · {} · serial `{}` · revision 0x{:02X}",
            info.part_number, info.serial_number, info.revision_code
        );
    }

    let lint = &report.lint;
    if lint.findings.is_empty() {
        let _ = writeln!(out, "- **Lint** · no findings");
    } else {
        let _ = writeln!(
            out,
            "- **Lint** · {} error(s), {} warning(s), {} info",
            lint.errors, lint.warnings, lint.infos
        );
        for finding in &lint.findings {
            let _ = writeln!(
                out,
                "  - {} · {} · {}",
                finding.severity, finding.code, finding.message
            );
        }
    }

    for note in &report.notes {
        let _ = writeln!(out, "- **Note** · {note}");
    }

    out
}

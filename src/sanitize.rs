//! Redacting the fields that identify one specific module.
//!
//! Every identifying field lives in the manufacturing information block, at
//! bytes 512..=554, which is past byte 509 and therefore **outside** the range
//! the base configuration CRC covers. Redacting them cannot disturb the CRC:
//! the integrity-checked region of the image stays byte for byte what the
//! module holds, and the stored CRC still matches.
//!
//! That is what makes a sanitised dump usable as evidence. A dump whose CRC
//! had to be recomputed after redaction would no longer be a faithful image of
//! the module, and the project would have to say so in every entry.

/// Byte range of the module serial number (bytes 517..=520).
pub const SERIAL_RANGE: std::ops::RangeInclusive<usize> = 517..=520;

/// Byte range of the module part number (bytes 521..=550).
pub const PART_NUMBER_RANGE: std::ops::RangeInclusive<usize> = 521..=550;

/// The serial number written in place of the real one.
///
/// The same placeholder the public sample set already uses, so a sanitised
/// dump is byte-compatible in form with the fixtures already in the tree.
pub const SERIAL_PLACEHOLDER: [u8; 4] = [0x99; 4];

/// The part number written in place of the real one, space padded to the
/// field width the way a real part number is padded.
pub const PART_NUMBER_PLACEHOLDER: &str = "REDACTED";

/// What to redact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Redaction {
    /// The module serial number, which is the unique device identifier.
    #[default]
    Serial,
    /// The serial number and the part number.
    SerialAndPartNumber,
    /// Nothing. The caller takes responsibility for the dump.
    None,
}

impl Redaction {
    /// A human-readable description of what this level removes.
    pub fn describe(self) -> &'static str {
        match self {
            Redaction::Serial => "module serial number",
            Redaction::SerialAndPartNumber => "module serial number and part number",
            Redaction::None => "nothing",
        }
    }
}

/// Apply a redaction to an image in place, returning the fields it replaced.///
/// A field that is not present in a short image is skipped rather than
/// padded: the tool never grows an image to make a field fit.
pub fn apply(bytes: &mut [u8], redaction: Redaction) -> Vec<&'static str> {
    let mut changed = Vec::new();

    if let Some(slice) = bytes.get_mut(SERIAL_RANGE) {
        slice.copy_from_slice(&SERIAL_PLACEHOLDER);
        changed.push("module serial number");
    }

    if redaction == Redaction::SerialAndPartNumber
        && let Some(slice) = bytes.get_mut(PART_NUMBER_RANGE)
    {
        slice.fill(b' ');
        let text = PART_NUMBER_PLACEHOLDER.as_bytes();
        slice[..text.len()].copy_from_slice(text);
        changed.push("module part number");
    }

    changed
}

/// The bytes of the image that a redaction would touch, for reporting.
pub fn redacted_ranges(redaction: Redaction) -> Vec<&'static str> {
    match redaction {
        Redaction::None => Vec::new(),
        Redaction::Serial => vec!["module serial number"],
        Redaction::SerialAndPartNumber => {
            vec!["module serial number", "module part number"]
        }
    }
}

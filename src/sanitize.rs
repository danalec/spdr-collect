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

/// Why the redaction map cannot be trusted.
#[derive(Debug)]
pub enum OffsetDrift {
    /// The serial number the library reads is not the one at [`SERIAL_RANGE`].
    Serial {
        /// The serial the library read.
        library: u32,
        /// The serial the bytes at [`SERIAL_RANGE`] hold.
        bytes: u32,
    },
    /// The part number the library reads is not the one at [`PART_NUMBER_RANGE`].
    PartNumber {
        /// The part number the library read.
        library: String,
        /// The part number the bytes at [`PART_NUMBER_RANGE`] hold.
        bytes: String,
    },
    /// The image is too short to carry the manufacturing block at all.
    TooShort,
}

impl core::fmt::Display for OffsetDrift {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OffsetDrift::Serial { library, bytes } => write!(
                f,
                "the library reads serial {library:08X} but bytes {SERIAL_RANGE:?} hold {bytes:08X}: the redaction map no longer matches the decoder"
            ),
            OffsetDrift::PartNumber { library, bytes } => write!(
                f,
                "the library reads part number {library:?} but bytes {PART_NUMBER_RANGE:?} hold {bytes:?}: the redaction map no longer matches the decoder"
            ),
            OffsetDrift::TooShort => f.write_str(
                "the image is too short to carry the manufacturing block, so the redaction map cannot be checked against it",
            ),
        }
    }
}

/// Check that the byte offsets this tool redacts are the ones the library
/// reads.
///
/// The offsets live here, in the tool, while the fields live in `spdr`, and
/// the library does not export them. If a field ever moved, the redaction
/// would silently stop covering it: the tool would report that it removed a
/// serial number that was still in the file. Comparing what the library
/// decoded against what these offsets hold turns that into a loud failure.
pub fn check_offsets(bytes: &[u8]) -> Result<(), OffsetDrift> {
    let Some(serial_bytes) = bytes.get(SERIAL_RANGE) else {
        return Err(OffsetDrift::TooShort);
    };
    let library = match spdr::decode_manufacturing(bytes) {
        Ok(manufacturing) => manufacturing,
        Err(_) => return Err(OffsetDrift::TooShort),
    };

    let bytes_serial = u32::from_be_bytes([
        serial_bytes[0],
        serial_bytes[1],
        serial_bytes[2],
        serial_bytes[3],
    ]);
    if bytes_serial != library.serial_number.0 {
        return Err(OffsetDrift::Serial {
            library: library.serial_number.0,
            bytes: bytes_serial,
        });
    }

    let Some(part_bytes) = bytes.get(PART_NUMBER_RANGE) else {
        return Err(OffsetDrift::TooShort);
    };
    let bytes_part = String::from_utf8_lossy(part_bytes)
        .trim_end_matches([' ', '\0'])
        .to_owned();
    if bytes_part != library.part_number {
        return Err(OffsetDrift::PartNumber {
            library: library.part_number.to_owned(),
            bytes: bytes_part,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PART_NUMBER_RANGE, SERIAL_PLACEHOLDER, SERIAL_RANGE, check_offsets};
    use std::path::Path;

    /// The browser page carries the same offsets as this module. If either
    /// moves, the page would silently stop redacting what the tool redacts,
    /// so the two are tied together here rather than by convention.
    #[test]
    fn the_browser_page_carries_the_same_offsets() {
        let page = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs")
            .join("collect.html");
        let text = std::fs::read_to_string(&page).expect("the page is in the repository");

        let expected = [
            format!(
                "const SERIAL_START = {}, SERIAL_END = {};",
                SERIAL_RANGE.start(),
                SERIAL_RANGE.end()
            ),
            format!(
                "const PART_START = {}, PART_END = {};",
                PART_NUMBER_RANGE.start(),
                PART_NUMBER_RANGE.end()
            ),
            format!(
                "const SERIAL_PLACEHOLDER = 0x{:02X};",
                SERIAL_PLACEHOLDER[0]
            ),
        ];
        for needle in expected {
            assert!(text.contains(&needle), "the page must carry {needle:?}");
        }
    }

    /// The offsets have to be the ones the library reads, or the redaction
    /// would cover the wrong bytes and still report success.
    #[test]
    fn the_offsets_match_the_decoder() {
        let bytes = read_fixture();
        check_offsets(&bytes).expect("the offsets must match the decoder");
    }

    /// The browser page has to name the module the same way the library does.
    /// The page carries its own copy of the encodings, because it cannot call
    /// Rust, so the two are checked against each other here rather than left
    /// to drift apart.
    #[test]
    fn the_browser_page_names_the_module_the_same_way() {
        let page = read_page();
        let bytes = read_fixture();
        let identity = spdr::decode_identity_and_base(&bytes).expect("the fixture decodes");

        let module = js_table(&page, "MODULE_TYPES");
        let found = module
            .iter()
            .find(|(key, _)| *key == bytes[3] & 0x0f)
            .map(|(_, name)| name.as_str());
        assert_eq!(
            found,
            Some(identity.module_type.to_string().as_str()),
            "the page must name the module type the way the library does"
        );

        let device = js_table(&page, "DEVICE_TYPES");
        let found = device
            .iter()
            .find(|(key, _)| *key == bytes[2])
            .map(|(_, name)| name.as_str());
        assert_eq!(
            found,
            Some(identity.device_type.to_string().as_str()),
            "the page must name the device type the way the library does"
        );
    }

    /// Read the browser page out of the repository.
    fn read_page() -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs")
            .join("collect.html");
        std::fs::read_to_string(&path).expect("the page is in the repository")
    }

    /// Read the fixture out of the repository.
    fn read_fixture() -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("teamgroup-ud5-6000_0104eef6.spd");
        std::fs::read(&path).expect("the fixture reads")
    }

    /// Parse one of the page's lookup tables into its entries.
    fn js_table(page: &str, name: &str) -> Vec<(u8, String)> {
        let marker = format!("const {name} = {{");
        let start = page
            .find(&marker)
            .unwrap_or_else(|| panic!("the page has {marker}"));
        let open = start + page[start..].find('{').expect("the table opens");
        let close = open + page[open..].find('}').expect("the table closes");
        let body = &page[open + 1..close];

        let mut entries = Vec::new();
        for entry in body.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (key, value) = entry.split_once(':').expect("a key and a value");
            let key = u8::from_str_radix(key.trim().trim_start_matches("0x"), 16)
                .expect("the key is hexadecimal");
            let value = value.trim().trim_matches('"').to_owned();
            entries.push((key, value));
        }
        entries
    }
}

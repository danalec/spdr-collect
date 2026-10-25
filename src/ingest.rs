//! Turning whatever a contributor has into the raw SPD image the project stores.
//!
//! Three inputs are accepted:
//!
//! - a **raw binary** image, which is what `dd` writes from a Linux sysfs
//!   `eeprom` path;
//! - a **hex dump**, which is what `hexdump -C`, `xxd`, `od` and `i2cdump`
//!   produce, and what `decode-dimms -x` reads;
//! - a **bare hex string**.
//!
//! Nothing is guessed silently. The format that was recognised is reported,
//! and a hex dump whose byte order inside a group is ambiguous is only read
//! the way the caller asked for.

use std::fmt;

/// The format an input was read as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A raw binary image.
    RawBinary,
    /// A hex dump with byte offsets.
    HexDump,
    /// A bare sequence of hex bytes.
    PlainHex,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Format::RawBinary => "raw binary",
            Format::HexDump => "hex dump",
            Format::PlainHex => "plain hex",
        })
    }
}

/// How the bytes inside a hex-dump group are ordered.
///
/// `xxd`, `hexdump -C` and `od -t x1` write bytes in file order. Plain
/// `hexdump`, without `-C`, writes 16-bit words swapped on a little-endian
/// host, which is the one format whose order cannot be told from the text
/// alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordOrder {
    /// Bytes are in file order inside each group.
    Natural,
    /// Each 16-bit group is byte-swapped.
    Swapped,
}

/// Why an input could not be read.
#[derive(Debug)]
pub enum IngestError {
    /// The input is text, but not a hex dump and not a bare hex string.
    NotHex,
    /// A hex dump line names an offset the previous line did not reach.
    OffsetGap { expected: usize, found: usize },
    /// A hex dump line starts before the previous line ended.
    OffsetOverlap { expected: usize, found: usize },
    /// A hex dump does not start at offset zero.
    NotAtStart { offset: usize },
    /// A hex dump has no data lines at all.
    Empty,
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IngestError::NotHex => {
                f.write_str("the input is text, but neither a hex dump nor a bare hex string")
            }
            IngestError::OffsetGap { expected, found } => {
                write!(f, "the hex dump skips from byte {expected} to byte {found}")
            }
            IngestError::OffsetOverlap { expected, found } => {
                write!(
                    f,
                    "the hex dump goes back to byte {found}, where {expected} was expected"
                )
            }
            IngestError::NotAtStart { offset } => {
                write!(f, "the hex dump starts at byte {offset}, not at byte 0")
            }
            IngestError::Empty => f.write_str("the hex dump has no data lines"),
        }
    }
}

/// What was read from an input file.
#[derive(Debug)]
pub struct Ingested {
    /// The bytes.
    pub bytes: Vec<u8>,
    /// The format the input was recognised as.
    pub format: Format,
    /// The byte order used inside hex-dump groups, when the input was one.
    pub word_order: Option<WordOrder>,
}

/// Read an input file into SPD bytes.
///
/// `force_swap` asks for the byte-swapped reading of a hex dump, which is what
/// plain `hexdump` writes on a little-endian host and which cannot be told
/// from `xxd` by looking at the text alone.
pub fn ingest(raw: &[u8], force_swap: bool) -> Result<Ingested, IngestError> {
    // A binary image carries NUL bytes; text does not. Anything that is not
    // valid UTF-8 is binary too.
    if raw.contains(&0) || std::str::from_utf8(raw).is_err() {
        return Ok(Ingested {
            bytes: raw.to_vec(),
            format: Format::RawBinary,
            word_order: None,
        });
    }
    let text = std::str::from_utf8(raw).unwrap_or_default();
    if text.lines().any(|line| split_offset(line).is_some()) {
        let (bytes, order) = parse_hex_dump(text, force_swap)?;
        return Ok(Ingested {
            bytes,
            format: Format::HexDump,
            word_order: Some(order),
        });
    }
    let bytes = parse_plain_hex(text).ok_or(IngestError::NotHex)?;
    Ok(Ingested {
        bytes,
        format: Format::PlainHex,
        word_order: None,
    })
}

/// Read an input as a raw binary image, whatever it looks like.
pub fn ingest_raw(raw: &[u8]) -> Ingested {
    Ingested {
        bytes: raw.to_vec(),
        format: Format::RawBinary,
        word_order: None,
    }
}

/// One data-bearing line of a hex dump.
struct DumpLine<'a> {
    offset: usize,
    tokens: Vec<&'a str>,
}

/// Parse a hex dump into the bytes it carries.
fn parse_hex_dump(text: &str, force_swap: bool) -> Result<(Vec<u8>, WordOrder), IngestError> {
    let mut lines: Vec<DumpLine<'_>> = Vec::new();
    let mut saw_colon = false;
    let mut saw_word = false;

    for line in text.lines() {
        let Some((offset, rest, had_colon)) = split_offset(line) else {
            continue;
        };
        let data = match rest.find('|') {
            Some(bar) => &rest[..bar],
            None => rest,
        };
        let mut tokens = Vec::new();
        for token in data.split_whitespace() {
            // The first token that is not a hex group starts the printable
            // gutter, on the formats that do not fence it with a bar.
            if !is_hex(token) || (token.len() != 2 && token.len() != 4) {
                break;
            }
            if token.len() == 4 {
                saw_word = true;
            }
            tokens.push(token);
        }
        if tokens.is_empty() {
            continue;
        }
        saw_colon |= had_colon;
        lines.push(DumpLine { offset, tokens });
    }

    if lines.is_empty() {
        return Err(IngestError::Empty);
    }

    // A colon means `xxd`, `i2cdump` or `eeprog`, all of which write bytes in
    // file order. Without a colon, 16-bit groups mean plain `hexdump`, which
    // byte-swaps on a little-endian host.
    let order = if force_swap {
        WordOrder::Swapped
    } else if saw_colon || !saw_word {
        WordOrder::Natural
    } else {
        WordOrder::Swapped
    };

    let mut bytes: Vec<u8> = Vec::new();
    for line in &lines {
        if bytes.is_empty() && line.offset != 0 {
            return Err(IngestError::NotAtStart {
                offset: line.offset,
            });
        }
        if line.offset > bytes.len() {
            return Err(IngestError::OffsetGap {
                expected: bytes.len(),
                found: line.offset,
            });
        }
        if line.offset < bytes.len() {
            return Err(IngestError::OffsetOverlap {
                expected: bytes.len(),
                found: line.offset,
            });
        }
        for token in &line.tokens {
            if token.len() == 2 {
                bytes.push(hex_byte(&token[0..2]));
            } else {
                let low = hex_byte(&token[0..2]);
                let high = hex_byte(&token[2..4]);
                if order == WordOrder::Swapped {
                    bytes.push(high);
                    bytes.push(low);
                } else {
                    bytes.push(low);
                    bytes.push(high);
                }
            }
        }
    }

    Ok((bytes, order))
}

/// Split a hex-dump line into its byte offset and the data that follows it.
///
/// Returns `None` for a line that carries no offset, which is how a bare hex
/// string is told apart from a hex dump.
fn split_offset(line: &str) -> Option<(usize, &str, bool)> {
    let trimmed = line.trim_start();
    let bytes = trimmed.as_bytes();
    let mut start = 0;
    if bytes.len() >= 2 && bytes[0] == b'0' && (bytes[1] == b'x' || bytes[1] == b'X') {
        start = 2;
    }
    let mut end = start;
    while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
        end += 1;
    }
    if end == start {
        return None;
    }
    let offset = usize::from_str_radix(trimmed.get(start..end)?, 16).ok()?;
    let rest = trimmed.get(end..)?;
    let had_colon = rest.starts_with(':');
    let rest = rest.strip_prefix(':').unwrap_or(rest).trim_start();
    Some((offset, rest, had_colon))
}

/// Parse a bare hex string into the bytes it carries.
fn parse_plain_hex(text: &str) -> Option<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() || compact.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(compact.len() / 2);
    for pair in compact.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(pair).ok()?;
        if !is_hex(pair) {
            return None;
        }
        bytes.push(hex_byte(pair));
    }
    Some(bytes)
}

/// Whether every character of `token` is a hexadecimal digit.
fn is_hex(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The value of a two-character hexadecimal token.
fn hex_byte(pair: &str) -> u8 {
    u8::from_str_radix(pair, 16).unwrap_or(0)
}

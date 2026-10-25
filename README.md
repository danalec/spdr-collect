# spdr-collect

The intake tool for the [`spdr`](https://github.com/The-Open-Memory-Initiative-OMI/spdr)
project: it turns the DDR5 SPD dump you have into the fixture the project
stores, with the fields that identify your module removed, and it prints the
provenance record the project asks for.

The decoding is already done, by `spdr`. The two things this tool adds are the
ones a contributor actually gets stuck on:

- **Reading whatever you have.** A raw binary image, a hex dump from
  `hexdump -C`, `xxd`, `od` or `i2cdump`, or a bare hex string. One command,
  no format detective work.
- **Removing the identifying fields.** The module serial number is a unique
  device identifier, and nobody wants to publish it. This tool removes it
  without touching a single byte the CRC covers, so the sanitised dump is
  still provably a faithful image of the module.

## Install

```sh
cargo install --path .          # from a checkout
cargo install spdr-collect      # once published
```

## Use

Validate a dump and see what it holds:

```sh
spdr-collect check dump.bin
```

Redact it and write the fixture:

```sh
spdr-collect sanitize dump.bin -o fixtures/my-module.spd
```

The report it prints is the record to paste into the project's
`docs/validated-against.md`:

```markdown
### Team Group Inc. UD5-6000 · UDIMM

- **Fixture** · `fixtures/my-module.spd` · 1024 bytes · sha256 `1b0d7373…`
- **Source** · `dump.bin` · raw binary · 1024 bytes · sha256 `cecfa75e…`
- **Sanitised** · module serial number
- **Base CRC** · computed `0x8021` · stored `0x8021` · match
- **Decoded** · identity and base configuration, base JEDEC timings, module-specific block, manufacturing information block, vendor overclock profiles
- **Module** · UDIMM · DDR5 SDRAM · 16 Gb per die · x8 · 8 bank groups x 4 banks · 1 die(s) · 1 rank(s) per channel · 2 channel(s) · 32-bit bus · 4800 MT/s base
- **Manufacturer** · Team Group Inc. · 2023-W37 · location 0x00
- **Part number** · UD5-6000 · serial `99999999` · revision 0x00
- **Lint** · no findings
```

`--json` prints the same facts as JSON instead.

## What gets redacted, and why it is safe

Every identifying field lives in the manufacturing information block, at bytes
512..=554. That region starts **past** byte 509, and the base configuration
CRC covers exactly bytes `0..=509`. So the fields that identify a module and
the bytes the CRC protects do not overlap:

| Field | Bytes | Redacted by default |
| --- | --- | --- |
| Module serial number | 517..=520 | yes |
| Module part number | 521..=550 | no |
| Manufacturer, date, location, revision | 512..=516, 551 | no |
| DRAM manufacturer, stepping | 552..=554 | no |

The consequence is the point: after redaction, the base CRC still recomputes
to the value the module itself stores. A sanitised dump needs no recomputed
CRC, so it stays a faithful image of the module rather than a reconstruction.

The serial number is replaced with `99999999`, the same placeholder the
project's public sample set already uses. The part number is kept by default,
because a SKU is public product data and keeping it makes the contribution
worth more; `--redact serial-and-part-number` removes it too.

## Getting a dump in the first place

This tool does not read hardware. The SPD lives on the SMBus, and getting it
out is a separate problem:

- **Linux** · the kernel exposes it as an EEPROM file:

  ```sh
  dd if=/sys/bus/i2c/drivers/ee1004/0-0050/eeprom of=dump.bin
  ```

  The bus and device address depend on the machine; `i2cdetect -l` lists
  them. `decode-dimms -x` reads a hex dump of the same file.

- **Windows** · an EFI tool such as RWEverything can write the SMBus to a
  file from a UEFI shell.

- **Anything** · `hexdump -C dump.bin > dump.txt` produces a dump this tool
  reads directly.

If your dump is a hex dump without a `hexdump -C` style offset, pass
`--swap-words`: plain `hexdump` writes 16-bit words byte-swapped on a
little-endian host, which is the one format whose order cannot be told from
the text alone.

## Exit codes

The same contract the `spdr` CLI uses:

| Code | Meaning |
| --- | --- |
| `0` | every section decoded |
| `1` | at least one section failed to decode, usually a truncated dump |
| `2` | the run could not happen: the file was unreadable or the format was not one this tool reads |

A CRC mismatch is reported, never blocking: it does not change the exit code,
and it never stops the fixture from being written. The report says so in
plain words.

## Tests

```sh
cargo test
```

The tests run against a copy of the fixture the `spdr` project validates
against, kept in `tests/fixtures/`, so they run in CI without the sibling
checkout. Its SHA-256 is the value the upstream project already records, which
is the independent check that the provenance hash this tool prints is right.

## Licence

Apache-2.0, the same as the `spdr` project.

# Test fixtures

`teamgroup-ud5-6000_0104eef6.spd` is an **unmodified copy** of the fixture the
[`spdr`](https://github.com/The-Open-Memory-Initiative-OMI/spdr) project
validates against, kept here so the tests run in CI, where the sibling
checkout is not available.

| | |
| --- | --- |
| Module | TEAMGROUP T-Create Expert 6000 (UD5-6000) |
| Size | 1024 bytes |
| sha256 | `cecfa75eb704272ad5b135e77a534cc416aec55a8daea54823b5dbf6d7761c98` |
| Base configuration CRC | computed `0x8021`, stored `0x8021` |

The hash is the one the upstream project already records in
`docs/numerical-claims.md`, which is what makes the provenance hash the tool
prints an independent check rather than a self-consistent one.

The serial number in this file, `0104EEF6`, is public: it is published in the
upstream repository as part of the module's reference data. Nothing here was
produced by this tool, so the file is byte-identical to the upstream fixture
rather than a sanitised copy of it.

Upstream provenance: `spdr/tests/fixtures/teamgroup-ud5-6000_0104eef6.spd`,
documented in the upstream `docs/validated-against.md`.

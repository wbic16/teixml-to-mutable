# teixml-to-mutable

Converts TEI-XML to **raw phext** — stage 0.1 of the TEI-XML → Phextura
migrator (SPEC 0.1 v3, task 5.4.6/5.5.5/5.6.5). Later stages, in order:
0.2 Mutable OS native export, 0.3 Phextura. They are not in this crate yet.

## What it does

`teixml-to-mutable convert <input-dir> -o <out.phext>` walks a directory
tree of TEI-XML files and writes **one multiversal phext chain** for the
whole directory (0x02-separated universes, 0x03-closed, framed with
libphext-rs 0.6 — the reference implementation; this crate contains no
hand-rolled phext parser):

- **$1** — an index scroll (path, SHA-256, size, storage class, original
  coordinate, first converted universe per file) followed by the original
  files verbatim as scrolls, in sorted path order. Files whose bytes are
  not valid UTF-8/ASCII (or contain phext break bytes) are stored as
  canonical binary scrolls (`phext-binary:1:base64`, libphext `binary`
  feature). Nothing is ever written to a sidecar file.
- **$2…** — converted universes. Every container element gets its own
  universe; a parent entry references it with a `@ref $N` scroll. Inside a
  universe, scrolls run in document order, each tagged: `@element`,
  `@attr` / `@value`, `@text` (every text node, including mixed content
  and tails), `@ref`, `@end`.

Files that are not well-formed XML are **named in the failure report**
(`<out>.failures.txt`, and in the $1 index) — never silently skipped;
their originals are still stored in $1 and extract byte-identically.

## Commands

```
teixml-to-mutable convert <input-dir> -o <out.phext>
teixml-to-mutable extract <chain.phext> <relative-path> -o <out-file>   # SHA-256 verified
teixml-to-mutable show    <chain.phext> '$2:1.1.1/1.1.1/1.1.1'          # mmap reader + index
teixml-to-mutable verify  <chain.phext> [--corpus <input-dir>]
```

The reader memory-maps the chain, builds a coordinate→span index in one
scan (all coordinates/offsets computed by libphext), and resolves
`$N:coordinate` addresses as slices into the mapping.

## Known limits of 0.1

- Comments, processing instructions and DOCTYPE are not represented in
  the converted universes (they are preserved in the $1 originals).
- Appending a whole new *file* to an existing chain is not implemented:
  $1's index cannot be extended without rewriting it. Appending member
  universes (`append_member`) leaves all prior bytes untouched. This is
  the spec's recorded open item for the WAL/chain-close composition.

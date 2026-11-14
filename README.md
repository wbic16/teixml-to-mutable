# teixml-to-mutable

Converts TEI-XML into the phext ecosystem, in stages (SPEC 0.1 v3, task
5.4.6/5.5.5/5.6.5): **0.1 raw phext** and **0.2 Mutable OS native export**
are in this crate; 0.3 Phextura follows, in order.

## Why this exists

### The archive is real, and it is staying

TEI (the Text Encoding Initiative) is the standard way the world's libraries,
archives, and scholarly editions encode texts — manuscripts, letters, critical
editions, catalogues. It has been continuously maintained since a planning
meeting at Vassar College in **November 1987**: first Guidelines in 1994 (P1),
an XML version in 2002 (P4), and the current P5 on 2 November 2007. Since 2001
the TEI Consortium — a non-profit membership body with an elected Technical
Council — has maintained the Guidelines as an open-source project.

Maintenance is **slow and deliberate, by design**: maintenance and feature
releases **every few months, with feature releases at least twice a year**
since 2007 (recent line: 4.9.0 in January 2025, 4.10.0 in August 2025, patches
4.10.1/4.10.2 within weeks; 4.11.0 February 2026, 4.12.0 July 2026). The
vocabulary — some 500+ elements — evolves backward-compatibly. A file encoded
in 2007 still parses today, and a file encoded today will parse in decades.
That conservatism is the point: TEI is a preservation format, and archives are
written once and kept forever.

### The problem: a preservation format is not a working format

Everything TEI preserves is locked inside nested XML trees:

- **No address for a fragment.** To touch one element, one attribute, or one
  text run, you parse the whole file into a tree that exists only inside one
  program's memory. Nothing outside that run can point at the piece.
- **No home for later scholarship.** Annotations — an editor's identification,
  a correction, a link between manuscripts — are standoff knowledge, but XML
  gives them two bad options: edit the original inline (the archive stops
  being the archive) or keep external files that drift away from what they
  describe.
- **No working surface.** The corpus is read by pipelines and rendered to web
  pages; it is not something people or agents can *work in* — query at
  fragment level, annotate, extend, and build on — without re-deriving the
  whole structure every time.

Meanwhile the corpus keeps growing: national libraries and collections like
the Wellcome Collection hold thousands of TEI manuscript descriptions (the
1,886-file corpus this tool is tested against is one collection), each one
hand-encoded scholarship that exists nowhere else.

### The bar an archival migrator has to clear

Originals like these **cannot be re-created**. A migration tool for archives
is therefore only acceptable if it is provably lossless: every original kept
byte-for-byte, verifiable by hash, extractable on demand — and the conversion
itself inspectable, reference by reference, rather than trusted. That is the
bar teixml-to-mutable is built to: the original files ride inside the phext
chain itself as the first universe (index + originals), every conversion is
checked against them, and `extract` gives any original back exactly.

### The upgrade

teixml-to-mutable gives TEI archives a first-class path into the phext
ecosystem, in stages:

1. **Raw phext (0.1)** — the XML tree lifted out of the file into a multiversal
   phext chain: each document a referenced universe, elements, attributes, and
   text as addressable scrolls, read at reference speed through
   memory-mapped access. Nothing is summarised or normalised away; the
   structure *is* the content.
2. **Mutable (0.2)** — the same content as native Mutable OS documents (the
   Cavern zip with its database and files), so archives become editable
   working documents — this is what lets people like Ian populate Mutable OS
   with real collections instead of demos.
3. **Phextura (0.3)** — TEI supported as a Phextura format, with standoff
   properties as the first-class home for the scholarship that accumulates
   *around* a text — layered over the original, never written into it.

TEI's own pace makes this safe to build: the format is not churning under us.
The value was never in chasing the spec — it is in unlocking what nearly four
decades of careful encoding already holds, and giving it addresses.

_TEI facts above sourced from tei-c.org and the Dublin Core Metadata
Standards Index, checked 2026-11-14._

## What it does

### 0.1 — raw phext

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

### 0.2 — Mutable OS native export

`teixml-to-mutable mutable <input-dir> -o <out.zip>` writes a **native
(disk-mode) Mutable Cavern** as a zip — the format Mutable OS opens
directly, no phext involved:

- One **native document** per converted TEI file
  (`Arabic/MS_423.xml` → `Arabic/MS_423.mutable.json`), in Mutable's
  `mutable-document` v1 envelope: a `document-block` root whose children
  are `standoff-editor-block`s built from the TEI block structure, with
  inline elements carried as standoff annotations (`tei/<element>` types,
  attributes in the annotation metadata). The title comes from the
  teiHeader (titleStmt/title, fallback msIdentifier/idno).
- Each document is **paired** the way Mutable's own native-only save
  pairs it: a `.mutable-pair-<sha256(resourceId)>/` home beside it with a
  version-2 receipt and generation record.
- The **original XML files** ride in the same tree verbatim (Mutable's
  vault scan files them under "other"), so the Cavern is lossless too.
- `.mutable/mutable.db` + `.mutable/audit.db` are a freshly established
  knowledge home (schema v10 / v1) built by applying **Mutable's own
  migration SQL byte-for-byte** (vendored under `sql/migrations/` —
  Mutable validates a database against those files' checksums and a
  structure hash, so identical bytes are what make it the real schema).
  Knowledge rows are derived state: Mutable's indexer populates them
  from the documents when the Cavern is opened.

### 0.3 — Phextura corpora with standoff

`teixml-to-mutable phextura <input-dir> -o <out-dir> [--no-vfs]`
writes **four files** per input directory, per the TEI profile
(`TEI.md`, DRAFT v0.1, in this repo and at the root of
[wbic16/phextura](https://github.com/wbic16/phextura)):

- `<name>.phext` — the **base corpus**: one Series per TEI document,
  0.2's segmentation reused (one segment = one Body scroll), bibentries
  in Collection 2, media headers in Collection 3, originals hoisted
  verbatim into Collection 5, metadata + manifest + object table in
  Collection 6.
- `<name>.standoff.phext` — the **standoff corpus**: one entry per
  element occurrence (plus one per comment and processing
  instruction), each with a full STANDOFF §2.3 survival kit, anchored
  to the base edition by a `px2:` address with a 16-hex edition pin
  and half-open Unicode-scalar spans over the target scroll's full
  stored text. Attributes ride as backslash-escaped `attr-` lines.
- `cavern.phext` — a **PhextVFS image** holding the pair as its files
  (`/<name>.phext`, `/<name>.standoff.phext`, documents stratum),
  for Mutable's phext mode; emitted by default, `--no-vfs` opts out.
  The pair is stored in the VFS binary format (base64 chunks) because
  phext bytes contain dimension breaks the VFS text format refuses;
  Mutable's own PhextVFS reader opens it, its L9 checksums verify,
  and the pair reads back byte-identical.
- `<name>.failures.txt` — the named-failure report, as in 0.1/0.2.

`verify-phextura <base.phext> <standoff.phext> [--corpus <dir>]` runs
the DESIGN §7 validator (checksums recompute, object table rebuilds
byte-for-byte) and, with `--corpus`, the reconstruction checker
(TEI-equivalence from the pair alone, originals byte-identical);
`relocate-phextura <base.phext> <standoff.phext>` runs the §2.4
anchor re-location harness (anchors resolve EXACT against the pinned
edition; drifted editions detach as ANCHOR-LOST/AMBIGUOUS, never
silently re-attach).

On the Wellcome corpus (1,886 files, 1,875 converted / 11 failed):
base 58,053,699 B (142,619 scrolls), standoff 341,302,423 B
(386,175 scrolls, 384,298 entries), image 533,212,798 B.

Files that are not well-formed XML are **named in the failure report**
(`<out>.failures.txt`) — never silently skipped; in 0.1 their originals
are still stored in $1 and extract byte-identically, and in 0.2 they
still ride in the Cavern tree.

## Commands

```
teixml-to-mutable convert <input-dir> -o <out.phext>
teixml-to-mutable mutable <input-dir> -o <out.zip>
teixml-to-mutable phextura <input-dir> -o <out-dir> [--no-vfs]
teixml-to-mutable extract <chain.phext> <relative-path> -o <out-file>   # SHA-256 verified
teixml-to-mutable show    <chain.phext> '$2:1.1.1/1.1.1/1.1.1'          # mmap reader + index
teixml-to-mutable verify  <chain.phext> [--corpus <input-dir>]
teixml-to-mutable verify-phextura <base.phext> <standoff.phext> [--corpus <input-dir>]
teixml-to-mutable relocate-phextura <base.phext> <standoff.phext>
```

The reader memory-maps the chain, builds a coordinate→span index in one
scan (all coordinates/offsets computed by libphext), and resolves
`$N:coordinate` addresses as slices into the mapping.

## Known limits

- Comments, processing instructions and DOCTYPE are not represented in
  the converted forms of 0.1 and 0.2 (they are preserved in the kept
  originals: $1 in 0.1, the Cavern tree in 0.2). In 0.3 they are:
  comments and PIs are standoff entries, DOCTYPE is metadata lines
  with its internal subset hoisted (TEI.md §4.1, §2.6).
- Appending a whole new *file* to an existing 0.1 chain is not
  implemented: $1's index cannot be extended without rewriting it.
  Appending member universes (`append_member`) leaves all prior bytes
  untouched. This is the spec's recorded open item for the WAL/chain-close
  composition.
- 0.2 ships no Markdown projections: documents are paired native-only
  (version-2 receipts), the save mode Mutable itself uses when no
  projection targets are defined.

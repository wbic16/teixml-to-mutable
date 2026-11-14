//! teixml-to-mutable 0.2 — Mutable OS native Cavern export.
//!
//! Produces a zip holding a native (disk-mode) Mutable Cavern: one native
//! document (`*.mutable.json`, mutable-document v1 envelope) per converted
//! TEI file, the original XML files verbatim in the same tree, a
//! `.mutable/` home whose `mutable.db` / `audit.db` are built by applying
//! Mutable's own migration SQL byte-for-byte, and a version-2 (native-only)
//! pair home per document — exactly the state Mutable's own native-only
//! save produces. Design + evidence: STAGE2-RECON.md (work files).
//!
//! The migration SQL under `sql/migrations/` is vendored unchanged from
//! wbic16/mutable-os (MIT; see sql/README.md). Mutable validates a database
//! against checksums and a structure hash computed from its own copies of
//! these files, so byte-identical SQL is what makes this the real schema
//! rather than a lookalike.

use crate::segment::{flatten, kept_map, segment_document};
use crate::{collect_xml_files, extract_title, parse_xml, rel_of, sha256_hex, Element};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Seek, Write};
use std::path::Path;

// ---------------------------------------------------------------------------
// Minimal JSON value with two writers matching JavaScript's JSON.stringify:
// `to_pretty_sorted` (keys sorted, 2-space indent — Mutable's nativeText
// canonical form) and `to_compact` (insertion order — receipt/intent/state
// files Mutable writes with plain JSON.stringify).

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

fn obj(mut pairs: Vec<(String, Json)>) -> Json {
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    Json::Obj(pairs)
}

fn escape_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

impl Json {
    /// JSON.stringify(value, null, 2): objects/arrays expand one item per
    /// line; empty ones stay inline as {} / [].
    pub fn to_pretty(&self) -> String {
        let mut s = String::new();
        self.write_pretty(&mut s, 0);
        s
    }
    fn write_pretty(&self, out: &mut String, indent: usize) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(n) => out.push_str(&n.to_string()),
            Json::Str(s) => escape_json_string(s, out),
            Json::Arr(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    out.push_str(&"  ".repeat(indent + 1));
                    item.write_pretty(out, indent + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&"  ".repeat(indent));
                out.push(']');
            }
            Json::Obj(pairs) => {
                if pairs.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                for (i, (k, v)) in pairs.iter().enumerate() {
                    out.push_str(&"  ".repeat(indent + 1));
                    escape_json_string(k, out);
                    out.push_str(": ");
                    v.write_pretty(out, indent + 1);
                    if i + 1 < pairs.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&"  ".repeat(indent));
                out.push('}');
            }
        }
    }
    /// JSON.stringify(value): compact, key order as constructed.
    pub fn to_compact(&self) -> String {
        let mut s = String::new();
        self.write_compact(&mut s);
        s
    }
    fn write_compact(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(n) => out.push_str(&n.to_string()),
            Json::Str(s) => escape_json_string(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_compact(out);
                }
                out.push(']');
            }
            Json::Obj(pairs) => {
                out.push('{');
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    escape_json_string(k, out);
                    out.push(':');
                    v.write_compact(out);
                }
                out.push('}');
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TEI -> Mutable document mapping (STAGE2-RECON.md §4)

/// The segmentation (block table, walk, keep rule) and the title chain
/// live in `crate::segment` and `crate` since stage 0.3 — one copy, shared
/// with the Phextura profile, so the stages cannot drift.

/// One kept segment as the document builder consumes it, with its inline
/// occurrences re-expressed in Mutable's inclusive Cell offsets.
struct SegView {
    owner: String,
    text: String,
    anns: Vec<AnnView>,
}

struct AnnView {
    id: usize,
    name: String,
    ns: String,
    attrs: Vec<(String, String)>,
    start: i64,
    end: i64,
    zero_width: bool,
}

/// Deterministic resourceId: a UUID-shaped digest of the source relative
/// path (SHA-256, version/variant bits set) — stable across runs, unique
/// per tree slot.
pub fn resource_id_for(rel: &str) -> String {
    uuid_shaped(&Sha256::digest(rel.as_bytes()))
}

/// Block identity in Mutable's knowledge store is VAULT-GLOBAL (the Block
/// table's primary key is the blockId alone, and the saved indexer's
/// duplicate pass compares identities across resources — proven on the
/// corpus Cavern, BUILD-LOG-0.2). Block ids are therefore UUID-shaped
/// digests of (resourceId, ordinal): unique across the vault, stable
/// across runs. Ordinal 0 is the document root.
fn block_id_for(resource_id: &str, ordinal: usize) -> String {
    uuid_shaped(&Sha256::digest(format!("{resource_id}:block:{ordinal}").as_bytes()))
}

fn uuid_shaped(digest: &[u8]) -> String {
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    format_uuid(&b)
}

fn format_uuid(b: &[u8; 16]) -> String {
    let h = |i: usize| format!("{:02x}", b[i]);
    let mut s = String::with_capacity(36);
    for i in 0..4 {
        s.push_str(&h(i));
    }
    s.push('-');
    for i in 4..6 {
        s.push_str(&h(i));
    }
    s.push('-');
    for i in 6..8 {
        s.push_str(&h(i));
    }
    s.push('-');
    for i in 8..10 {
        s.push_str(&h(i));
    }
    s.push('-');
    for i in 10..16 {
        s.push_str(&h(i));
    }
    s
}

fn new_uuid_v4() -> String {
    let mut b: [u8; 16] = rand::random();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format_uuid(&b)
}

/// The document filename for a source relative path: `MS.xml` ->
/// `MS.mutable.json`, folders preserved.
pub fn document_rel_for(rel: &str) -> String {
    let stem = rel.strip_suffix(".xml").or_else(|| rel.strip_suffix(".XML")).unwrap_or(rel);
    format!("{}.mutable.json", stem)
}

/// One converted Mutable document, ready to write into the Cavern tree.
#[derive(Debug)]
pub struct MutableDocument {
    pub resource_id: String,
    pub title: String,
    /// Cavern-relative path of the document file ("/" separators).
    pub doc_rel: String,
    /// Canonical serialized bytes (Mutable's nativeText form + "\n").
    pub json: String,
    /// Concatenation of the blocks' text in reading order.
    pub plain_text: String,
    pub blocks: usize,
    pub annotations: usize,
}

/// Build the Mutable document for one parsed TEI file (0.1 model element).
pub fn build_document(rel: &str, root: &Element) -> MutableDocument {
    let resource_id = resource_id_for(rel);
    let title = extract_title(root, rel);
    let doc_rel = document_rel_for(rel);
    let filename = doc_rel.rsplit('/').next().unwrap_or(&doc_rel).to_string();
    let folder = match doc_rel.rfind('/') {
        Some(i) => doc_rel[..i].to_string(),
        None => ".".to_string(),
    };

    let flat = flatten(root);
    let segmentation = segment_document(root, &flat);
    let kept = kept_map(&segmentation);
    // Drop segments carrying nothing: whitespace-only text with no
    // annotations is inter-block formatting, not content (recon §4.4).
    // Annotation ids run in walk order exactly as the pre-0.3 Builder
    // assigned them: kept segments preserve walk order, and a segment
    // carrying annotations is never dropped, so the sequence is identical.
    // Offsets convert from the shared half-open scalar spans to Mutable's
    // inclusive Cell offsets: end − 1, with start == end staying zero-width
    // at end = start − 1 (the pre-0.3 Builder's exact convention).
    let mut next_ann = 0usize;
    let mut segs: Vec<SegView> = Vec::new();
    for (raw, keep) in segmentation.segments.iter().zip(kept.iter()) {
        if keep.is_none() {
            continue;
        }
        let mut anns = Vec::with_capacity(raw.inlines.len());
        for occ in &raw.inlines {
            next_ann += 1;
            let start = occ.start as i64;
            let zero_width = occ.start == occ.end;
            anns.push(AnnView {
                id: next_ann,
                name: occ.name.clone(),
                ns: occ.ns.clone(),
                attrs: occ.attrs.clone(),
                start,
                end: if zero_width { start - 1 } else { occ.end as i64 - 1 },
                zero_width,
            });
        }
        segs.push(SegView { owner: raw.owner_name.clone(), text: raw.text.clone(), anns });
    }

    let plain_text: String = segs.iter().map(|s| s.text.as_str()).collect();
    let annotations: usize = segs.iter().map(|s| s.anns.len()).sum();

    let mut blocks: Vec<Json> = Vec::with_capacity(segs.len() + 1);
    let mut edges: Vec<Json> = Vec::with_capacity(segs.len());
    for (i, seg) in segs.iter().enumerate() {
        let block_id = block_id_for(&resource_id, i + 1);
        edges.push(obj(vec![
            ("kind".into(), Json::Str("owned".into())),
            ("placementId".into(), Json::Str(format!("p{}", i + 1))),
            (
                "target".into(),
                obj(vec![
                    ("blockId".into(), Json::Str(block_id.clone())),
                    ("kind".into(), Json::Str("local".into())),
                ]),
            ),
        ]));
        let anns: Vec<Json> = seg
            .anns
            .iter()
            .map(|a| {
                let mut pairs: Vec<(String, Json)> = vec![
                    ("end".into(), Json::Int(a.end)),
                    ("id".into(), Json::Str(format!("a{}", a.id))),
                    ("start".into(), Json::Int(a.start)),
                    ("type".into(), Json::Str(format!("tei/{}", a.name))),
                ];
                if a.zero_width {
                    pairs.push(("isZeroWidth".into(), Json::Bool(true)));
                }
                if !a.attrs.is_empty() || !a.ns.is_empty() {
                    let mut meta: Vec<(String, Json)> = Vec::new();
                    if !a.attrs.is_empty() {
                        meta.push((
                            "attributes".into(),
                            obj(a.attrs.iter().map(|(k, v)| (k.clone(), Json::Str(v.clone()))).collect()),
                        ));
                    }
                    if !a.ns.is_empty() {
                        meta.push(("namespace".into(), Json::Str(a.ns.clone())));
                    }
                    pairs.push(("metadata".into(), obj(meta)));
                }
                obj(pairs)
            })
            .collect();
        let inline = if seg.text.is_empty() {
            Json::Arr(vec![])
        } else {
            Json::Arr(vec![obj(vec![
                ("kind".into(), Json::Str("text".into())),
                ("text".into(), Json::Str(seg.text.clone())),
            ])])
        };
        blocks.push(obj(vec![
            ("id".into(), Json::Str(block_id)),
            ("inline".into(), inline),
            (
                "properties".into(),
                obj(vec![
                    ("standoffProperties".into(), Json::Arr(anns)),
                    ("teiElement".into(), Json::Str(seg.owner.clone())),
                ]),
            ),
            ("type".into(), Json::Str("standoff-editor-block".into())),
        ]));
    }
    let root_id = block_id_for(&resource_id, 0);
    let root_block = obj(vec![
        ("children".into(), Json::Arr(edges)),
        ("id".into(), Json::Str(root_id.clone())),
        (
            "properties".into(),
            obj(vec![(
                "metadata".into(),
                obj(vec![
                    ("documentId".into(), Json::Str(resource_id.clone())),
                    ("filename".into(), Json::Str(filename)),
                    ("folder".into(), Json::Str(folder)),
                    ("title".into(), Json::Str(title.clone())),
                ]),
            )]),
        ),
        ("type".into(), Json::Str("document-block".into())),
    ]);
    blocks.push(root_block);
    // nativeText sorts blocks by id before serializing.
    blocks.sort_by(|a, b| block_id_of(a).cmp(block_id_of(b)));

    let envelope = obj(vec![
        ("definitionOwnerBlockIds".into(), Json::Arr(vec![])),
        (
            "document".into(),
            obj(vec![
                ("blocks".into(), Json::Arr(blocks)),
                ("format".into(), Json::Str("codex-portable-resource-gate".into())),
                ("resourceId".into(), Json::Str(resource_id.clone())),
                (
                    "root".into(),
                    obj(vec![
                        ("kind".into(), Json::Str("owned".into())),
                        ("placementId".into(), Json::Str("p0".into())),
                        (
                            "target".into(),
                            obj(vec![
                                ("blockId".into(), Json::Str(root_id)),
                                ("kind".into(), Json::Str("local".into())),
                            ]),
                        ),
                    ]),
                ),
                ("version".into(), Json::Int(2)),
            ]),
        ),
        ("format".into(), Json::Str("mutable-document".into())),
        ("resourceId".into(), Json::Str(resource_id.clone())),
        ("valueEncoding".into(), Json::Str("codex-authored-value-v1".into())),
        ("version".into(), Json::Int(1)),
    ]);
    let mut json = envelope.to_pretty();
    json.push('\n');
    MutableDocument {
        resource_id,
        title,
        doc_rel,
        json,
        plain_text,
        blocks: segs.len(),
        annotations,
    }
}

fn block_id_of(block: &Json) -> &str {
    if let Json::Obj(pairs) = block {
        for (k, v) in pairs {
            if k == "id" {
                if let Json::Str(s) = v {
                    return s;
                }
            }
        }
    }
    ""
}

// ---------------------------------------------------------------------------
// Knowledge databases: Mutable's own migration SQL, applied the way its
// migration runner applies it (one transaction; per step the SchemaInfo
// rows schemaVersion/databaseKind/vaultGuid/migration:<n>=sha256(sql),
// plus the application_id and user_version pragmas).

const MUTABLE_MIGRATIONS: &[&str] = &[
    include_str!("../sql/migrations/mutable/0001-foundation.sql"),
    include_str!("../sql/migrations/mutable/0002-semantic-knowledge.sql"),
    include_str!("../sql/migrations/mutable/0003-scholarly-identities.sql"),
    include_str!("../sql/migrations/mutable/0004-encyclopedia.sql"),
    include_str!("../sql/migrations/mutable/0005-iiif.sql"),
    include_str!("../sql/migrations/mutable/0006-resources.sql"),
    include_str!("../sql/migrations/mutable/0007-deterministic-academic.sql"),
    include_str!("../sql/migrations/mutable/0008-propositions.sql"),
    include_str!("../sql/migrations/mutable/0009-cardex.sql"),
    include_str!("../sql/migrations/mutable/0010-cardex-soft-delete.sql"),
];
const AUDIT_MIGRATIONS: &[&str] = &[include_str!("../sql/migrations/audit/0001-foundation.sql")];
const MUTABLE_APP_ID: i64 = 0x4D55_544B;
const AUDIT_APP_ID: i64 = 0x4D55_5441;

/// Create one knowledge database exactly as Mutable's establishment does:
/// fresh file, all migrations applied fresh, WAL journal like the
/// foundation's configured open leaves behind.
fn create_database(path: &Path, kind: &str, migrations: &[&str], app_id: i64, vault_guid: &str) -> Result<(), String> {
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| format!("remove {}: {}", path.display(), e))?;
    }
    let mut conn = rusqlite::Connection::open(path).map_err(|e| format!("open db {}: {}", path.display(), e))?;
    let run = (|| -> Result<(), String> {
        // Mutable's fresh path runs migrations with foreign keys off (the
        // rebuild rule) and restores them after; DDL-only content makes the
        // state immaterial, but mirror it anyway.
        conn.pragma_update(None, "foreign_keys", "OFF").map_err(|e| e.to_string())?;
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        for (i, sql) in migrations.iter().enumerate() {
            let version = (i + 1) as i64;
            tx.execute_batch(sql).map_err(|e| format!("migration {}:{}: {}", kind, version, e))?;
            let checksum = sha256_hex(sql.as_bytes());
            for (key, value) in [
                ("schemaVersion", version.to_string()),
                ("databaseKind", kind.to_string()),
                ("vaultGuid", vault_guid.to_string()),
                (&format!("migration:{}", version), checksum),
            ] {
                tx.execute(
                    "INSERT INTO SchemaInfo(key,value) VALUES(?1,?2) \
                     ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    rusqlite::params![key, value],
                )
                .map_err(|e| e.to_string())?;
            }
            tx.pragma_update(None, "application_id", app_id).map_err(|e| e.to_string())?;
            tx.pragma_update(None, "user_version", version).map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(|e| e.to_string())?;
        // The foundation configures WAL on open; a clean close then leaves
        // the file in WAL format with no -wal/-shm companions.
        let mode: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
            .map_err(|e| e.to_string())?;
        if mode != "wal" {
            return Err(format!("journal_mode is {}, expected wal", mode));
        }
        Ok(())
    })();
    let close = conn.close().map_err(|(_, e)| e.to_string());
    run.and(close)
}

// ---------------------------------------------------------------------------
// Pair homes (version 2, native-only — the state Mutable's own native-only
// save publishes; STAGE2-RECON.md §2). Receipt and intent use Mutable's
// exact JSON.stringify key order.

/// Deterministic generation id for the import save (matches
/// Mutable's /^[a-zA-Z0-9-]+$/ generation rule).
pub const IMPORT_GENERATION: &str = "tei-import-1";

fn pair_home_name(resource_id: &str) -> String {
    format!(".mutable-pair-{}", sha256_hex(resource_id.as_bytes()))
}

fn receipt_json(doc: &MutableDocument, native_hash: &str) -> String {
    let native_name = doc.doc_rel.rsplit('/').next().unwrap_or(&doc.doc_rel);
    let markdown_name = native_name.strip_suffix(".mutable.json").map(|s| format!("{}.md", s)).unwrap_or_else(|| format!("{}.md", native_name));
    Json::Obj(vec![
        ("version".into(), Json::Int(2)),
        ("resourceId".into(), Json::Str(doc.resource_id.clone())),
        ("generation".into(), Json::Str(IMPORT_GENERATION.into())),
        ("nativeName".into(), Json::Str(native_name.into())),
        ("markdownName".into(), Json::Str(markdown_name)),
        ("nativeHash".into(), Json::Str(native_hash.into())),
        ("markdownHash".into(), Json::Null),
    ])
    .to_compact()
}

fn intent_json(doc: &MutableDocument, native_hash: &str) -> String {
    let native_name = doc.doc_rel.rsplit('/').next().unwrap_or(&doc.doc_rel);
    let markdown_name = native_name.strip_suffix(".mutable.json").map(|s| format!("{}.md", s)).unwrap_or_else(|| format!("{}.md", native_name));
    Json::Obj(vec![
        ("version".into(), Json::Int(2)),
        ("resourceId".into(), Json::Str(doc.resource_id.clone())),
        ("generation".into(), Json::Str(IMPORT_GENERATION.into())),
        ("nativeName".into(), Json::Str(native_name.into())),
        ("markdownName".into(), Json::Str(markdown_name)),
        ("profile".into(), Json::Str("mutable-document".into())),
        ("nativeHash".into(), Json::Str(native_hash.into())),
        ("markdownHash".into(), Json::Null),
        (
            "expected".into(),
            Json::Obj(vec![("native".into(), Json::Null), ("markdown".into(), Json::Null)]),
        ),
    ])
    .to_compact()
}

// ---------------------------------------------------------------------------
// Cavern zip export

#[derive(Debug)]
pub struct MutableEntry {
    pub rel: String,
    pub error: Option<String>,
    pub doc_rel: Option<String>,
    pub resource_id: Option<String>,
    pub title: Option<String>,
    pub blocks: usize,
    pub annotations: usize,
}

#[derive(Debug)]
pub struct MutableSummary {
    pub entries: Vec<MutableEntry>,
    pub vault_guid: String,
    pub documents: usize,
    pub out_bytes: u64,
}

fn zip_options(mode: u32) -> zip::write::SimpleFileOptions {
    zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(mode)
        .last_modified_time(zip::DateTime::default())
}

fn write_entry<W: Write + Seek>(zip: &mut zip::ZipWriter<W>, name: &str, mode: u32, bytes: &[u8]) -> Result<(), String> {
    zip.start_file(name, zip_options(mode)).map_err(|e| format!("zip {}: {}", name, e))?;
    zip.write_all(bytes).map_err(|e| format!("zip write {}: {}", name, e))?;
    Ok(())
}

fn write_entry_from_file<W: Write + Seek>(zip: &mut zip::ZipWriter<W>, name: &str, mode: u32, file: &Path) -> Result<(), String> {
    zip.start_file(name, zip_options(mode)).map_err(|e| format!("zip {}: {}", name, e))?;
    let mut f = std::fs::File::open(file).map_err(|e| format!("open {}: {}", file.display(), e))?;
    std::io::copy(&mut f, zip).map_err(|e| format!("zip write {}: {}", name, e))?;
    Ok(())
}

/// Export a directory of TEI-XML as a Mutable native Cavern zip.
/// Every source file is accounted for: converted (a document), or named
/// in the returned entries with its error — zero silent skips, as in 0.1.
/// The original XML rides in the tree verbatim either way.
pub fn export_mutable(dir: &Path, out: &Path) -> Result<MutableSummary, String> {
    let files = collect_xml_files(dir)?;
    let vault_guid = new_uuid_v4();

    // Build the knowledge databases in a scratch dir, then stream them in.
    let scratch = std::env::temp_dir().join(format!("teixml-mutable-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).map_err(|e| format!("scratch {}: {}", scratch.display(), e))?;
    let mutable_db = scratch.join("mutable.db");
    let audit_db = scratch.join("audit.db");
    let db_result = (|| -> Result<(), String> {
        create_database(&mutable_db, "mutable", MUTABLE_MIGRATIONS, MUTABLE_APP_ID, &vault_guid)?;
        create_database(&audit_db, "audit", AUDIT_MIGRATIONS, AUDIT_APP_ID, &vault_guid)
    })();
    if let Err(e) = db_result {
        let _ = std::fs::remove_dir_all(&scratch);
        return Err(e);
    }

    let out_file = std::fs::File::create(out).map_err(|e| format!("create {}: {}", out.display(), e))?;
    let mut zip = zip::ZipWriter::new(std::io::BufWriter::new(out_file));
    let result = (|| -> Result<Vec<MutableEntry>, String> {
        let mut dirs: HashSet<String> = HashSet::new();
        let ensure_dir = |zip: &mut zip::ZipWriter<_>, d: &str, dirs: &mut HashSet<String>| -> Result<(), String> {
            if d.is_empty() || d == "." || !dirs.insert(d.to_string()) {
                return Ok(());
            }
            zip.add_directory(format!("{}/", d), zip_options(0o755)).map_err(|e| format!("zip dir {}: {}", d, e))
        };

        // .mutable home first: Mutable's establishment order.
        zip.add_directory(".mutable/", zip_options(0o700)).map_err(|e| format!("zip dir .mutable: {}", e))?;
        write_entry_from_file(&mut zip, ".mutable/mutable.db", 0o600, &mutable_db)?;
        write_entry_from_file(&mut zip, ".mutable/audit.db", 0o600, &audit_db)?;
        let state = Json::Obj(vec![
            ("v".into(), Json::Int(1)),
            ("mode".into(), Json::Str("native".into())),
            ("cavernGuid".into(), Json::Str(vault_guid.clone())),
        ])
        .to_compact();
        write_entry(&mut zip, ".mutable/cavern-state.json", 0o600, state.as_bytes())?;
        write_entry(&mut zip, ".mutable/writer.lock", 0o600, &[])?;

        let mut entries: Vec<MutableEntry> = Vec::with_capacity(files.len());
        let mut used_doc_rels: HashSet<String> = HashSet::new();
        for path in &files {
            let rel = rel_of(dir, path);
            let bytes = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
            // The original always rides in the tree (the scan's "other"
            // category); stage 2 stays lossless independent of conversion.
            if let Some(parent) = rel.rfind('/') {
                let mut acc = String::new();
                for part in rel[..parent].split('/') {
                    if !acc.is_empty() {
                        acc.push('/');
                    }
                    acc.push_str(part);
                    ensure_dir(&mut zip, &acc.clone(), &mut dirs)?;
                }
            }
            write_entry(&mut zip, &rel, 0o644, &bytes)?;

            let mut entry = MutableEntry {
                rel: rel.clone(),
                error: None,
                doc_rel: None,
                resource_id: None,
                title: None,
                blocks: 0,
                annotations: 0,
            };
            match parse_xml(&bytes) {
                Ok(root) => {
                    let doc = build_document(&rel, &root);
                    if !used_doc_rels.insert(doc.doc_rel.clone()) {
                        entry.error = Some(format!("document path collision: {}", doc.doc_rel));
                        entries.push(entry);
                        continue;
                    }
                    let native_hash = sha256_hex(doc.json.as_bytes());
                    write_entry(&mut zip, &doc.doc_rel, 0o644, doc.json.as_bytes())?;
                    // Version-2 pair home beside the document.
                    let folder_prefix = match doc.doc_rel.rfind('/') {
                        Some(i) => format!("{}/", &doc.doc_rel[..i]),
                        None => String::new(),
                    };
                    let home = format!("{}{}", folder_prefix, pair_home_name(&doc.resource_id));
                    zip.add_directory(format!("{}/", home), zip_options(0o755)).map_err(|e| format!("zip dir {}: {}", home, e))?;
                    write_entry(&mut zip, &format!("{}/receipt.json", home), 0o644, receipt_json(&doc, &native_hash).as_bytes())?;
                    let gen_dir = format!("{}/{}", home, IMPORT_GENERATION);
                    zip.add_directory(format!("{}/", gen_dir), zip_options(0o755)).map_err(|e| format!("zip dir {}: {}", gen_dir, e))?;
                    write_entry(&mut zip, &format!("{}/native", gen_dir), 0o644, doc.json.as_bytes())?;
                    write_entry(&mut zip, &format!("{}/intent.json", gen_dir), 0o644, intent_json(&doc, &native_hash).as_bytes())?;
                    write_entry(&mut zip, &format!("{}/writer.lock", home), 0o644, &[])?;
                    entry.doc_rel = Some(doc.doc_rel);
                    entry.resource_id = Some(doc.resource_id);
                    entry.title = Some(doc.title);
                    entry.blocks = doc.blocks;
                    entry.annotations = doc.annotations;
                }
                Err(e) => entry.error = Some(e),
            }
            entries.push(entry);
        }
        Ok(entries)
    })();
    let finish = zip.finish().map_err(|e| format!("zip finish: {}", e));
    let _ = std::fs::remove_dir_all(&scratch);
    let entries = result?;
    finish?;
    let documents = entries.iter().filter(|e| e.error.is_none()).count();
    let out_bytes = std::fs::metadata(out).map(|m| m.len()).unwrap_or(0);
    Ok(MutableSummary {
        entries,
        vault_guid,
        documents,
        out_bytes,
    })
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_xml;

    fn el(xml: &str) -> Element {
        parse_xml(xml.as_bytes()).unwrap()
    }

    #[test]
    fn json_pretty_matches_stringify_shape() {
        let v = obj(vec![
            ("b".into(), Json::Arr(vec![Json::Int(1), Json::Str("x\ny".into())])),
            ("a".into(), obj(vec![])),
            ("c".into(), Json::Arr(vec![])),
        ]);
        assert_eq!(
            v.to_pretty(),
            "{\n  \"a\": {},\n  \"b\": [\n    1,\n    \"x\\ny\"\n  ],\n  \"c\": []\n}"
        );
    }

    #[test]
    fn mixed_content_order_and_ranges() {
        let root = el(r#"<TEI xmlns="http://www.tei-c.org/ns/1.0"><text><body><div><p>one <hi rend="b">two</hi> three</p><p>four</p></div></body></text></TEI>"#);
        let doc = build_document("x.xml", &root);
        assert_eq!(doc.plain_text, "one two threefour");
        assert_eq!(doc.blocks, 2);
        assert_eq!(doc.annotations, 1);
        // hi covers "two": cells 4..=6 of the first block
        assert!(doc.json.contains("\"start\": 4"), "{}", doc.json);
        assert!(doc.json.contains("\"end\": 6"), "{}", doc.json);
        assert!(doc.json.contains("\"type\": \"tei/hi\""), "{}", doc.json);
        assert!(doc.json.contains("\"rend\": \"b\""), "{}", doc.json);
    }

    #[test]
    fn tails_and_nested_blocks_split_segments() {
        let root = el(r#"<TEI><body><div>pre<p>mid</p>post</div></body></TEI>"#);
        let doc = build_document("x.xml", &root);
        assert_eq!(doc.plain_text, "premidpost");
        assert_eq!(doc.blocks, 3);
    }

    #[test]
    fn zero_width_annotation_for_empty_inline() {
        let root = el(r#"<TEI><body><p>ab<lb/>cd</p></body></TEI>"#);
        let doc = build_document("x.xml", &root);
        assert_eq!(doc.plain_text, "abcd");
        assert!(doc.json.contains("\"isZeroWidth\": true"), "{}", doc.json);
        assert!(doc.json.contains("\"start\": 2"), "{}", doc.json);
        assert!(doc.json.contains("\"end\": 1"), "{}", doc.json);
    }

    #[test]
    fn astral_chars_count_as_one_cell() {
        let root = el("<TEI><body><p>\u{1F600}<hi>x</hi></p></body></TEI>");
        let doc = build_document("x.xml", &root);
        assert!(doc.json.contains("\"start\": 1"), "{}", doc.json);
        assert!(doc.json.contains("\"end\": 1"), "{}", doc.json);
    }

    #[test]
    fn title_fallbacks() {
        let root = el(r#"<TEI><teiHeader><fileDesc><titleStmt><title>  A  Title </title></titleStmt></fileDesc></teiHeader><text/></TEI>"#);
        assert_eq!(build_document("d/f.xml", &root).title, "A Title");
        let root = el(r#"<TEI><teiHeader><fileDesc><sourceDesc><msDesc><msIdentifier><idno>MS 42</idno></msIdentifier></msDesc></sourceDesc></fileDesc></teiHeader></TEI>"#);
        assert_eq!(build_document("d/f.xml", &root).title, "MS 42");
        let root = el(r#"<TEI><text><body><p>hi</p></body></text></TEI>"#);
        assert_eq!(build_document("d/My File.xml", &root).title, "My File");
    }

    #[test]
    fn envelope_shape() {
        let root = el(r#"<TEI><text><body><p>hi</p></body></text></TEI>"#);
        let doc = build_document("a/b.xml", &root);
        assert!(doc.json.starts_with("{\n  \"definitionOwnerBlockIds\": []"), "{}", &doc.json[..80]);
        assert!(doc.json.contains("\"format\": \"mutable-document\""));
        assert!(doc.json.contains("\"documentId\": \"") );
        assert!(doc.json.contains("\"folder\": \"a\""));
        assert!(doc.json.contains("\"filename\": \"b.mutable.json\""));
        assert!(doc.json.ends_with("}\n"));
        assert_eq!(doc.doc_rel, "a/b.mutable.json");
    }

    #[test]
    fn block_ids_are_vault_global() {
        // Mutable's Block table keys on blockId alone: ids must differ
        // across documents, not just within one (indexer duplicate pass).
        let root = el(r#"<TEI><text><body><p>hi</p></body></text></TEI>"#);
        let a = build_document("a/one.xml", &root);
        let b = build_document("a/two.xml", &root);
        let ids = |json: &str| -> Vec<String> {
            json.rmatch_indices("\"id\": \"")
                .map(|(i, _)| json[i + 7..i + 43].to_string())
                .collect()
        };
        let (ia, ib) = (ids(&a.json), ids(&b.json));
        assert_eq!(ia.len(), 2, "root + one segment");
        for id in &ia {
            assert!(!ib.contains(id), "block id {id} reused across documents");
        }
        // Deterministic: rebuilding the same document yields the same ids.
        let a2 = build_document("a/one.xml", &root);
        assert_eq!(ia, ids(&a2.json));
    }

    #[test]
    fn databases_carry_mutable_schema() {
        let dir = std::env::temp_dir().join(format!("teixml-dbtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let guid = new_uuid_v4();
        create_database(&dir.join("mutable.db"), "mutable", MUTABLE_MIGRATIONS, MUTABLE_APP_ID, &guid).unwrap();
        create_database(&dir.join("audit.db"), "audit", AUDIT_MIGRATIONS, AUDIT_APP_ID, &guid).unwrap();
        for (file, kind, app_id, version, rows) in [
            ("mutable.db", "mutable", MUTABLE_APP_ID, 10i64, 14i64),
            ("audit.db", "audit", AUDIT_APP_ID, 1i64, 5i64),
        ] {
            let conn = rusqlite::Connection::open(dir.join(file)).unwrap();
            let count: i64 = conn.query_row("SELECT count(*) FROM SchemaInfo", [], |r| r.get(0)).unwrap();
            assert_eq!(count, rows, "{}", file);
            let g: String = conn.query_row("SELECT value FROM SchemaInfo WHERE key='vaultGuid'", [], |r| r.get(0)).unwrap();
            assert_eq!(g, guid);
            let k: String = conn.query_row("SELECT value FROM SchemaInfo WHERE key='databaseKind'", [], |r| r.get(0)).unwrap();
            assert_eq!(k, kind);
            let aid: i64 = conn.pragma_query_value(None, "application_id", |r| r.get(0)).unwrap();
            assert_eq!(aid, app_id);
            let uv: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
            assert_eq!(uv, version);
            let mode: String = conn.pragma_query_value(None, "journal_mode", |r| r.get(0)).unwrap();
            assert_eq!(mode, "wal");
            // migration checksums recorded are the SQL files' own hashes
            let migrations: &[&str] = if kind == "mutable" { MUTABLE_MIGRATIONS } else { AUDIT_MIGRATIONS };
            for (i, sql) in migrations.iter().enumerate() {
                let recorded: String = conn
                    .query_row("SELECT value FROM SchemaInfo WHERE key=?1", [format!("migration:{}", i + 1)], |r| r.get(0))
                    .unwrap();
                assert_eq!(recorded, sha256_hex(sql.as_bytes()), "{} migration {}", file, i + 1);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

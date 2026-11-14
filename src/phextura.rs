//! teixml-to-mutable 0.3 — Phextura output (SPEC-0.3; Will's rulings
//! D1–D5 of 2026-11-14; D6 open — no PhextVFS image is emitted).
//!
//! Per input directory, emits a self-contained pair:
//!   `<name>.phext`          — the base corpus (phextura DESIGN.md layout)
//!   `<name>.standoff.phext` — the standoff corpus (phextura STANDOFF.md)
//! plus `<name>.failures.txt` naming every file that did not convert.
//!
//! Layout in brief (the normative statement is TEI.md, the profile
//! document in the phextura repository):
//! - Base: corpus root Z = 1.1.1; Series 1 is corpus-level (Collection 6:
//!   manifest, object-table index scrolls, minting ledger); one Series
//!   per TEI document in sorted relative-path order. Per document,
//!   Collection 1 holds Body scrolls (one kept segment per scroll, the
//!   shared segmentation of `crate::segment`), Collection 2 bibliography
//!   entries, Collection 3 media headers, Collection 5 the hoisted
//!   original (+ any DOCTYPE internal subset), Collection 6 the document
//!   metadata scroll.
//! - Standoff: one entry per element occurrence (D5), plus comment/PI
//!   entries (D3), each carrying the full STANDOFF §2.3 survival kit.
//!   Anchors address the pinned base edition by L2 key where the
//!   occurrence is itself a keyed object, else by coordinate; spans are
//!   half-open Unicode-scalar offsets over the target scroll's full
//!   stored text, header lines included.
//!
//! Emission seam (D6): the exporter first builds a per-document layout
//! (coordinates, scroll texts, entry records) and then hands it to two
//! independent writers — `write_base` and `write_standoff`. A future
//! PhextVFS writer would be a third consumer of the same layout; adding
//! it touches neither writer.
//!
//! All phext handling goes through libphext-rs. Both files are written
//! in libphext canonical form, `normalize(implode(map))`; an edition's
//! checksum is libphext `checksum` (xxh3-128) over that form with the
//! manifest's checksum line excluded.

use crate::segment::{flatten, kept_map, segment_document, Flat};
use crate::{
    classify, collect_xml_files, collapse_ws, element_text, extract_title, first_named,
    parse_xml_full, rel_of, sha256_hex, Element, Node, ParsedDocument, StorageClass,
};
use libphext::phext;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub const PROFILE_VERSION: &str = "0.1";
pub const TEI_NS: &str = "http://www.tei-c.org/ns/1.0";
pub const CONVERTER: &str = concat!("teixml-to-mutable ", env!("CARGO_PKG_VERSION"));

/// L2 key kinds, in object-table index order (LAYER2 §1.4 + profile
/// extension kind `tei-element`, minted on cite only).
pub const KIND_ORDER: &[&str] = &["paper", "section", "bibentry", "figure", "tei-element"];

/// Attributes whose values are treated as references (SPEC-0.3 §3.5).
pub const POINTING_ATTRS: &[&str] = &[
    "ref", "target", "corresp", "decls", "sameAs", "copyOf", "next", "prev", "ana",
];

// ---------------------------------------------------------------------------
// Coordinates

/// A full 9-component phext coordinate (Z/Y/X), the address currency of
/// this module; converted to libphext coordinates only at the implode
/// boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct C9 {
    pub z: (u32, u32, u32),
    pub y: (u32, u32, u32),
    pub x: (u32, u32, u32),
}

impl C9 {
    pub fn new(z: (u32, u32, u32), y: (u32, u32, u32), x: (u32, u32, u32)) -> C9 {
        C9 { z, y, x }
    }
    pub fn addr(&self) -> String {
        format!(
            "{}.{}.{}/{}.{}.{}/{}.{}.{}",
            self.z.0, self.z.1, self.z.2, self.y.0, self.y.1, self.y.2, self.x.0, self.x.1,
            self.x.2
        )
    }
    pub fn phext(&self) -> phext::Coordinate {
        phext::to_coordinate(&self.addr())
    }
    pub fn parse(s: &str) -> Option<C9> {
        let mut parts = s.split('/');
        let tri = |p: Option<&str>| -> Option<(u32, u32, u32)> {
            let p = p?;
            let mut it = p.split('.');
            Some((
                it.next()?.parse().ok()?,
                it.next()?.parse().ok()?,
                it.next()?.parse().ok()?,
            ))
        };
        let z = tri(parts.next())?;
        let y = tri(parts.next())?;
        let x = tri(parts.next())?;
        if parts.next().is_some() {
            return None;
        }
        Some(C9 { z, y, x })
    }
}

fn body_coord(series: u32, book: u32, chapter: u32, section: u32, scroll: u32) -> C9 {
    C9::new((1, 1, series), (1, 1, book), (chapter, section, scroll))
}
fn coll_coord(series: u32, collection: u32, chapter: u32, section: u32, scroll: u32) -> C9 {
    C9::new((1, 1, series), (collection, 1, 1), (chapter, section, scroll))
}

/// The corpus-level manifest coordinate (Series 1, Collection 6).
pub fn manifest_coord() -> C9 {
    coll_coord(1, 6, 1, 1, 1)
}
/// The standoff's own metadata coordinate (its Collection 6, Series 1).
pub fn standoff_meta_coord() -> C9 {
    coll_coord(1, 6, 1, 1, 1)
}

// ---------------------------------------------------------------------------
// D4 header-line escaping: backslash escapes for `\`, newline, tab,
// carriage return, and leading/trailing space (`\ `). One physical line
// always carries exactly one value; unescape is strict (unknown escapes
// are an error, never a guess).

pub fn escape_value(v: &str) -> String {
    let n = v.chars().count();
    let mut out = String::with_capacity(v.len());
    for (i, c) in v.chars().enumerate() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' ' if i == 0 || i + 1 == n => out.push_str("\\ "),
            c => out.push(c),
        }
    }
    out
}

pub fn unescape_value(v: &str) -> Result<String, String> {
    let mut out = String::with_capacity(v.len());
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(' ') => out.push(' '),
            Some(other) => return Err(format!("unknown escape \\{}", other)),
            None => return Err("trailing backslash in escaped value".into()),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Key slugs (LAYER2 §2.4 grammar [a-z][a-z0-9-]*)

pub fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut last_dash = true; // suppresses leading dashes
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        out.push_str("x");
    }
    if !out.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false) {
        out.insert_str(0, "id-");
    }
    out
}

/// Corpus-global key registry: uniqueness per kind by traversal-order
/// suffixing (`-2`, `-3`, …), and the minting record the base ledger
/// scroll is written from.
#[derive(Default)]
struct KeyRegistry {
    used: HashMap<(String, String), C9>,
    pub minted: Vec<(String, String, C9)>, // (kind, slug, coord), mint order
}

impl KeyRegistry {
    fn mint(&mut self, kind: &str, base_slug: &str, coord: C9) -> String {
        let mut slug = base_slug.to_string();
        let mut n = 2u32;
        while self.used.contains_key(&(kind.to_string(), slug.clone())) {
            slug = format!("{}-{}", base_slug, n);
            n += 1;
        }
        self.used.insert((kind.to_string(), slug.clone()), coord);
        self.minted.push((kind.to_string(), slug.clone(), coord));
        slug
    }
}

// ---------------------------------------------------------------------------
// Timestamps (ISO 8601 UTC, seconds) and edition checksums

pub fn iso_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    iso_from_unix(secs)
}

pub fn iso_from_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    // civil-from-days (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        m,
        d,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

const CHECKSUM_PREFIX: &str = "checksum: xxh3-128:";

/// Remove any `checksum: xxh3-128:` line from a scroll's text.
pub fn strip_checksum_line(text: &str) -> String {
    text.lines()
        .filter(|l| !l.starts_with(CHECKSUM_PREFIX))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The edition checksum: libphext xxh3-128 over the canonical form of
/// the corpus with the checksum line excluded from its manifest scroll.
pub fn edition_checksum(map: &HashMap<phext::Coordinate, String>, manifest: C9) -> String {
    let mut m = map.clone();
    if let Some(text) = m.get_mut(&manifest.phext()) {
        *text = strip_checksum_line(text);
    }
    phext::checksum(&phext::normalize(&phext::implode(m)))
}

pub fn canonical_bytes(map: &HashMap<phext::Coordinate, String>) -> Vec<u8> {
    phext::normalize(&phext::implode(map.clone())).into_bytes()
}

// ---------------------------------------------------------------------------
// Per-document layout: coordinates, keys, and base scroll texts.
// The writers consume a finished layout; a future PhextVFS writer would
// consume the same struct (the D6 seam).

struct FilePlan {
    rel: String,
    sha256: String,
    size: usize,
    class: StorageClass,
    error: Option<String>,
    /// All xml:id values in the document.
    ids: HashSet<String>,
    /// xml:id values that are the target of an intra-file fragment
    /// reference from a pointing attribute.
    cited: HashSet<String>,
}

struct SegScroll {
    coord: C9,
    /// Scalar offset where the segment text begins inside the scroll.
    prefix: usize,
    /// Total scalars in the scroll.
    total: usize,
}

struct DocLayout {
    series: u32,
    scrolls: Vec<(C9, String)>,
    seg_scroll: HashMap<usize, SegScroll>, // raw seg idx (kept only)
    seg_owner: HashMap<usize, usize>,      // raw seg idx -> owning elem
    kept_order: Vec<usize>,                // kept raw seg idxs, in order
    owner_kept: HashMap<usize, Vec<usize>>, // elem -> kept raw segs it owns
    inline_home: HashMap<usize, (usize, usize, usize)>, // elem -> (raw seg, start, end)
    meta_coord: C9,
    id_to_key: HashMap<String, (String, String)>,
    elem_key: HashMap<usize, (String, String)>,
    /// elem -> the coordinate its keyed object lives at (when keyed).
    obj_coord: HashMap<usize, C9>,
}

impl DocLayout {
    /// The anchor for one element occurrence: (coord, start, end) as a
    /// half-open scalar span over the target scroll's full stored text.
    /// Fallback chain (profile §3.2): own segment whole-scroll → point at
    /// the text start of the first scroll in the subtree → next scroll in
    /// the document → previous scroll's text end → metadata point 0.
    fn home_of(&self, flat: &Flat, elem: usize) -> (C9, usize, usize) {
        if let Some(&(raw, start, end)) = self.inline_home.get(&elem) {
            let ss = &self.seg_scroll[&raw];
            return (ss.coord, ss.prefix + start, ss.prefix + end);
        }
        if let Some(raws) = self.owner_kept.get(&elem) {
            if let Some(raw) = raws.first() {
                let ss = &self.seg_scroll[raw];
                return (ss.coord, 0, ss.total);
            }
        }
        let end = flat.subtree_end[elem];
        for raw in &self.kept_order {
            let owner = self.seg_owner[raw];
            if owner >= elem && owner < end {
                let ss = &self.seg_scroll[raw];
                return (ss.coord, ss.prefix, ss.prefix);
            }
        }
        for raw in &self.kept_order {
            if self.seg_owner[raw] >= end {
                let ss = &self.seg_scroll[raw];
                return (ss.coord, ss.prefix, ss.prefix);
            }
        }
        for raw in self.kept_order.iter().rev() {
            if self.seg_owner[raw] < elem {
                let ss = &self.seg_scroll[raw];
                return (ss.coord, ss.total, ss.total);
            }
        }
        (self.meta_coord, 0, 0)
    }
}

/// Elements that head a LAYER2 `section` object when headed (profile §3).
pub const SECTION_ELEMENTS: &[&str] = &[
    "div", "div1", "div2", "div3", "div4", "div5", "div6", "div7", "msItem",
];

fn elem_children(flat: &Flat) -> Vec<Vec<usize>> {
    let mut out: Vec<Vec<usize>> = vec![Vec::new(); flat.len()];
    for i in 0..flat.len() {
        if let Some(p) = flat.parent[i] {
            out[p].push(i);
        }
    }
    out
}

/// Book assignment (profile §2.2): Book 1 = teiHeader matter, Book 2 =
/// text matter, front/body/back successive Books, any other top-level
/// matter its own Book in order.
fn assign_books(
    flat: &Flat,
    children: &[Vec<usize>],
) -> (Vec<u32>, HashMap<u32, usize>) {
    let mut roots: Vec<usize> = Vec::new();
    for &c in &children[0] {
        let name = flat.nodes[c].name.as_str();
        if name == "teiHeader" {
            roots.push(c);
        } else if name == "text" {
            let subs: Vec<usize> = children[c]
                .iter()
                .cloned()
                .filter(|&g| matches!(flat.nodes[g].name.as_str(), "front" | "body" | "back"))
                .collect();
            if subs.is_empty() {
                roots.push(c);
            } else {
                roots.extend(subs);
            }
        } else {
            roots.push(c);
        }
    }
    let mut number: HashMap<usize, u32> = HashMap::new();
    let mut root_of_book: HashMap<u32, usize> = HashMap::new();
    for (i, r) in roots.iter().enumerate() {
        number.insert(*r, (i + 1) as u32);
        root_of_book.insert((i + 1) as u32, *r);
    }
    let first = 1;
    let mut book_of = vec![first; flat.len()];
    fn mark(
        flat: &Flat,
        children: &[Vec<usize>],
        number: &HashMap<usize, u32>,
        book_of: &mut Vec<u32>,
        idx: usize,
        book: u32,
    ) {
        book_of[idx] = book;
        for &c in &children[idx] {
            let b = number.get(&c).copied().unwrap_or(book);
            mark(flat, children, number, book_of, c, b);
        }
    }
    mark(flat, children, &number, &mut book_of, 0, first);
    (book_of, root_of_book)
}

/// Chain of flat indices from `elem` up to (excluding) `stop`, elem first.
fn chain_to(flat: &Flat, elem: usize, stop: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut cur = elem;
    while cur != stop {
        out.push(cur);
        match flat.parent[cur] {
            Some(p) => cur = p,
            None => break,
        }
    }
    out
}

fn first_descendant_named(flat: &Flat, elem: usize, name: &str) -> Option<usize> {
    ((elem + 1)..flat.subtree_end[elem]).find(|&i| flat.nodes[i].name == name)
}

fn year_of(flat: &Flat, elem: usize) -> Option<String> {
    let date = first_descendant_named(flat, elem, "date")?;
    let el = flat.nodes[date];
    if let Some((_, when)) = el.attrs.iter().find(|(k, _)| k == "when") {
        let digits: String = when.chars().take(4).collect();
        if digits.len() == 4 && digits.chars().all(|c| c.is_ascii_digit()) {
            return Some(digits);
        }
    }
    find_year(&collapse_ws(&flat.text[date]))
}

fn find_year(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        if bytes[i..i + 4].iter().all(|b| b.is_ascii_digit())
            && (i == 0 || !bytes[i - 1].is_ascii_digit())
            && (i + 4 == bytes.len() || !bytes[i + 4].is_ascii_digit())
        {
            return Some(s[i..i + 4].to_string());
        }
        i += 1;
    }
    None
}

fn sanitize_line(s: &str) -> String {
    s.chars().map(|c| if c == '\t' || c == '\n' || c == '\r' { ' ' } else { c }).collect()
}

struct SectionCand {
    elem: usize,
    coord: Option<C9>,
    slug_base: String,
}

struct BibCand {
    elem: usize,
    coord: C9,
    author: Option<String>,
    title: Option<String>,
    year: Option<String>,
    text: String,
    slug_base: String,
}

/// Originals scrolls (header + content) shared by converted and failed
/// documents: the hoisted original is what makes the pair self-contained
/// (ruling D2).
fn originals_scrolls(plan: &FilePlan, series: u32, bytes: &[u8]) -> Vec<(C9, String)> {
    let mut out = Vec::new();
    let header = format!(
        "source-path: {}\nsource-sha256: {}\nsize: {}\nstorage: {}",
        plan.rel,
        plan.sha256,
        plan.size,
        plan.class.as_str()
    );
    out.push((coll_coord(series, 5, 1, 1, 1), header));
    if plan.size > 0 {
        let content = match plan.class {
            StorageClass::Text => String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|_| libphext::binary::encode_scroll(bytes)),
            StorageClass::Binary => libphext::binary::encode_scroll(bytes),
        };
        out.push((coll_coord(series, 5, 1, 1, 2), content));
    }
    out
}

fn failure_layout(plan: &FilePlan, series: u32, bytes: &[u8]) -> DocLayout {
    let mut scrolls = originals_scrolls(plan, series, bytes);
    let meta = format!(
        "source-path: {}\nsource-sha256: {}\nconversion: failed — {}",
        plan.rel,
        plan.sha256,
        sanitize_line(plan.error.as_deref().unwrap_or("unknown error"))
    );
    scrolls.push((coll_coord(series, 6, 1, 1, 1), meta));
    DocLayout {
        series,
        scrolls,
        seg_scroll: HashMap::new(),
        seg_owner: HashMap::new(),
        kept_order: Vec::new(),
        owner_kept: HashMap::new(),
        inline_home: HashMap::new(),
        meta_coord: coll_coord(series, 6, 1, 1, 1),
        id_to_key: HashMap::new(),
        elem_key: HashMap::new(),
        obj_coord: HashMap::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_layout(
    plan: &FilePlan,
    parsed: &ParsedDocument,
    bytes: &[u8],
    series: u32,
    registry: &mut KeyRegistry,
    externals: &mut HashSet<String>,
) -> DocLayout {
    let root = &parsed.root;
    let flat = flatten(root);
    let seg = segment_document(root, &flat);
    let kept = kept_map(&seg);
    let children = elem_children(&flat);
    let meta_coord = coll_coord(series, 6, 1, 1, 1);

    // --- segment coordinates via book/chapter/section grouping
    let (book_of, root_of_book) = assign_books(&flat, &children);
    let mut seg_coord: HashMap<usize, C9> = HashMap::new();
    let mut seg_owner: HashMap<usize, usize> = HashMap::new();
    let mut owner_kept: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut inline_home: HashMap<usize, (usize, usize, usize)> = HashMap::new();
    let mut kept_order: Vec<usize> = Vec::new();
    for (raw, s) in seg.segments.iter().enumerate() {
        if kept[raw].is_none() {
            continue;
        }
        kept_order.push(raw);
        seg_owner.insert(raw, s.owner);
        owner_kept.entry(s.owner).or_default().push(raw);
        for occ in &s.inlines {
            inline_home.insert(occ.elem, (raw, occ.start, occ.end));
        }
    }
    {
        let mut books: Vec<u32> = kept_order.iter().map(|&r| book_of[seg.segments[r].owner]).collect();
        books.sort();
        books.dedup();
        for book in books {
            let broot = root_of_book.get(&book).copied().unwrap_or(0);
            let (mut chapter, mut section, mut scroll) = (0u32, 0u32, 0u32);
            let mut prev: Option<(Option<usize>, Option<usize>)> = None;
            for &raw in &kept_order {
                let owner = seg.segments[raw].owner;
                if book_of[owner] != book {
                    continue;
                }
                let chain = chain_to(&flat, owner, broot);
                let a1 = if owner == broot { None } else { chain.last().copied() };
                let a2 = if chain.len() >= 2 { Some(chain[chain.len() - 2]) } else { None };
                let key = (a1, a2);
                if prev != Some(key) {
                    if prev.is_none() || a1 != prev.map(|p| p.0).unwrap_or(None) {
                        chapter += 1;
                        section = 1;
                    } else {
                        section += 1;
                    }
                    scroll = 1;
                    prev = Some(key);
                } else {
                    scroll += 1;
                }
                seg_coord.insert(raw, body_coord(series, book, chapter, section, scroll));
            }
        }
    }
    let home_coord = |elem: usize| -> C9 {
        if let Some(&(raw, _, _)) = inline_home.get(&elem) {
            return seg_coord[&raw];
        }
        if let Some(raws) = owner_kept.get(&elem) {
            if let Some(raw) = raws.first() {
                return seg_coord[raw];
            }
        }
        let end = flat.subtree_end[elem];
        for &raw in &kept_order {
            let o = seg_owner[&raw];
            if o >= elem && o < end {
                return seg_coord[&raw];
            }
        }
        for &raw in &kept_order {
            if seg_owner[&raw] >= end {
                return seg_coord[&raw];
            }
        }
        for &raw in kept_order.iter().rev() {
            if seg_owner[&raw] < elem {
                return seg_coord[&raw];
            }
        }
        meta_coord
    };

    // --- object candidates
    // sections: headed div-family / msItem elements
    let mut section_cands: Vec<SectionCand> = Vec::new();
    let mut section_ordinal = 0usize;
    for i in 0..flat.len() {
        let name = flat.nodes[i].name.as_str();
        if !SECTION_ELEMENTS.contains(&name) {
            continue;
        }
        let head = first_descendant_named(&flat, i, "head");
        let head = match head {
            Some(h) => h,
            None => continue,
        };
        section_ordinal += 1;
        let head_text = collapse_ws(&flat.text[head]);
        let slug_base = if !head_text.is_empty() {
            slugify(&head_text)
        } else if let Some((_, id)) = flat.nodes[i].attrs.iter().find(|(k, _)| k == "xml:id") {
            slugify(id)
        } else {
            format!("s-{}-{}", series, section_ordinal)
        };
        section_cands.push(SectionCand { elem: i, coord: None, slug_base });
    }
    {
        // claim heading scrolls: first the head's own first segment,
        // then (for heads owning no segment) the first scroll in the
        // element's subtree, if still unclaimed.
        let mut claimed: HashMap<C9, usize> = HashMap::new();
        for cand in section_cands.iter_mut() {
            let head = first_descendant_named(&flat, cand.elem, "head").unwrap();
            if let Some(raws) = owner_kept.get(&head) {
                if let Some(raw) = raws.first() {
                    let c = seg_coord[raw];
                    if !claimed.contains_key(&c) {
                        claimed.insert(c, cand.elem);
                        cand.coord = Some(c);
                    }
                }
            }
        }
        for cand in section_cands.iter_mut() {
            if cand.coord.is_some() {
                continue;
            }
            let end = flat.subtree_end[cand.elem];
            for &raw in &kept_order {
                let o = seg_owner[&raw];
                if o >= cand.elem && o < end {
                    let c = seg_coord[&raw];
                    if !claimed.contains_key(&c) {
                        claimed.insert(c, cand.elem);
                        cand.coord = Some(c);
                    }
                    break;
                }
            }
        }
    }
    // bibliography entries: bibl / biblStruct not nested in another
    let mut bib_cands: Vec<BibCand> = Vec::new();
    for i in 0..flat.len() {
        let name = flat.nodes[i].name.as_str();
        if name != "bibl" && name != "biblStruct" {
            continue;
        }
        let mut nested = false;
        let mut p = flat.parent[i];
        while let Some(pi) = p {
            let pn = flat.nodes[pi].name.as_str();
            if pn == "bibl" || pn == "biblStruct" {
                nested = true;
                break;
            }
            p = flat.parent[pi];
        }
        if nested {
            continue;
        }
        let text = collapse_ws(&flat.text[i]);
        if text.is_empty() {
            continue;
        }
        let author = first_descendant_named(&flat, i, "author")
            .or_else(|| first_descendant_named(&flat, i, "editor"))
            .map(|a| collapse_ws(&flat.text[a]))
            .filter(|t| !t.is_empty());
        let title = first_descendant_named(&flat, i, "title")
            .map(|t| collapse_ws(&flat.text[t]))
            .filter(|t| !t.is_empty());
        let year = year_of(&flat, i);
        let slug_base = match (&author, &year) {
            (Some(a), Some(y)) => {
                // "Surname, First" library form takes the part before
                // the comma; otherwise the last name token.
                let surname = match a.split_once(',') {
                    Some((last, _)) => last.trim().to_string(),
                    None => a.rsplit(char::is_whitespace).next().unwrap_or(a).to_string(),
                };
                format!("{}-{}", slugify(&surname), y)
            }
            (Some(a), None) => slugify(a),
            (None, _) => match &title {
                Some(t) => slugify(&t.split_whitespace().take(5).collect::<Vec<_>>().join(" ")),
                None => format!("bib-{}-{}", series, bib_cands.len() + 1),
            },
        };
        bib_cands.push(BibCand {
            elem: i,
            coord: coll_coord(series, 2, 1, 1, (bib_cands.len() + 1) as u32),
            author,
            title,
            year,
            text,
            slug_base,
        });
    }
    // figures: graphic elements carrying a url
    let mut figures: Vec<(usize, String, C9)> = Vec::new();
    for i in 0..flat.len() {
        if flat.nodes[i].name != "graphic" {
            continue;
        }
        if let Some((_, url)) = flat.nodes[i].attrs.iter().find(|(k, _)| k == "url") {
            externals.insert(url.clone());
            let coord = coll_coord(series, 3, 1, 1, (figures.len() + 1) as u32);
            figures.push((i, url.clone(), coord));
        }
    }

    // --- minting, in document order; the paper first
    let paper_slug_base = match first_named(root, "msIdentifier") {
        Some(ident) => match first_named(ident, "idno") {
            Some(idno) => {
                let t = collapse_ws(&element_text(idno));
                if t.is_empty() {
                    slugify(&plan.rel)
                } else {
                    slugify(&t)
                }
            }
            None => slugify(&plan.rel),
        },
        None => slugify(&plan.rel),
    };
    let paper_slug = registry.mint("paper", &paper_slug_base, meta_coord);
    let mut elem_key: HashMap<usize, (String, String)> = HashMap::new();
    let mut obj_coord: HashMap<usize, C9> = HashMap::new();
    obj_coord.insert(0, meta_coord);
    let mut id_to_key: HashMap<String, (String, String)> = HashMap::new();
    let mut seg_key_line: HashMap<C9, String> = HashMap::new();
    let mut bib_slug: HashMap<usize, String> = HashMap::new();
    let mut fig_slug: HashMap<usize, String> = HashMap::new();
    let cand_by_elem: HashMap<usize, &SectionCand> =
        section_cands.iter().map(|c| (c.elem, c)).collect();
    let bib_by_elem: HashMap<usize, &BibCand> = bib_cands.iter().map(|c| (c.elem, c)).collect();
    let fig_by_elem: HashMap<usize, &C9> =
        figures.iter().map(|(e, _, c)| (*e, c)).collect();
    for i in 0..flat.len() {
        if i == 0 {
            if let Some((_, id)) = flat.nodes[0].attrs.iter().find(|(k, _)| k == "xml:id") {
                if plan.cited.contains(id) {
                    id_to_key.insert(id.clone(), ("paper".to_string(), paper_slug.clone()));
                }
            }
        }
        if let Some(cand) = cand_by_elem.get(&i) {
            if let Some(coord) = cand.coord {
                let slug = registry.mint("section", &cand.slug_base, coord);
                elem_key.insert(i, ("section".to_string(), slug.clone()));
                obj_coord.insert(i, coord);
                seg_key_line.insert(coord, format!("section:{}", slug));
            }
        }
        if let Some(cand) = bib_by_elem.get(&i) {
            let slug = registry.mint("bibentry", &cand.slug_base, cand.coord);
            elem_key.insert(i, ("bibentry".to_string(), slug.clone()));
            obj_coord.insert(i, cand.coord);
            bib_slug.insert(i, slug);
        }
        if let Some(coord) = fig_by_elem.get(&i) {
            let url = &figures.iter().find(|(e, _, _)| *e == i).unwrap().1;
            let stem = url.rsplit('/').next().unwrap_or(url);
            let stem = stem.rsplit_once('.').map(|(s, _)| s).unwrap_or(stem);
            let slug = registry.mint("figure", &slugify(stem), **coord);
            elem_key.insert(i, ("figure".to_string(), slug.clone()));
            obj_coord.insert(i, **coord);
            fig_slug.insert(i, slug);
        }
        if let Some((_, id)) = flat.nodes[i].attrs.iter().find(|(k, _)| k == "xml:id") {
            if plan.cited.contains(id) && !id_to_key.contains_key(id) {
                if let Some(k) = elem_key.get(&i) {
                    id_to_key.insert(id.clone(), k.clone());
                } else {
                    let hc = home_coord(i);
                    let slug = registry.mint("tei-element", &slugify(id), hc);
                    elem_key.insert(i, ("tei-element".to_string(), slug.clone()));
                    obj_coord.insert(i, hc);
                    id_to_key.insert(id.clone(), ("tei-element".to_string(), slug));
                }
            }
        }
    }

    // --- compose scrolls
    let mut scrolls: Vec<(C9, String)> = Vec::new();
    let mut seg_scroll: HashMap<usize, SegScroll> = HashMap::new();
    for &raw in &kept_order {
        let s = &seg.segments[raw];
        let owner = flat.nodes[s.owner];
        let coord = seg_coord[&raw];
        let mut lines: Vec<String> = Vec::new();
        lines.push(if owner.name == "head" { "@heading".to_string() } else { "@prose".to_string() });
        if let Some(k) = seg_key_line.get(&coord) {
            lines.push(format!("key: {}", k));
        }
        lines.push(format!("tei-element: {}", owner.name));
        if owner.ns != TEI_NS {
            lines.push(format!(
                "tei-namespace: {}",
                if owner.ns.is_empty() { "(none)".to_string() } else { owner.ns.clone() }
            ));
        }
        lines.push(String::new());
        let prefix_text = lines.join("\n");
        let text = format!("{}\n{}", prefix_text, s.text);
        let prefix = prefix_text.chars().count() + 1;
        let total = text.chars().count();
        seg_scroll.insert(raw, SegScroll { coord, prefix, total });
        scrolls.push((coord, text));
    }
    for cand in &bib_cands {
        let slug = &bib_slug[&cand.elem];
        let mut lines = vec![format!("key: bibentry:{}", slug)];
        if let Some(a) = &cand.author {
            lines.push(format!("author: {}", escape_value(a)));
        }
        if let Some(t) = &cand.title {
            lines.push(format!("title: {}", escape_value(t)));
        }
        if let Some(y) = &cand.year {
            lines.push(format!("year: {}", y));
        }
        lines.push(format!("text: {}", escape_value(&cand.text)));
        scrolls.push((cand.coord, lines.join("\n")));
    }
    for (elem, url, coord) in &figures {
        let slug = &fig_slug[elem];
        let text = format!(
            "@figure\nkey: figure:{}\nurl: {}\ntei-element: graphic\nchecksum: absent — external, not hoisted",
            slug, url
        );
        scrolls.push((*coord, text));
    }
    scrolls.extend(originals_scrolls(plan, series, bytes));
    if let Some(dt) = &parsed.doctype {
        if let Some(subset) = &dt.internal_subset {
            let class = classify(subset.as_bytes());
            let header = format!(
                "source-path: {}\ndoctype-name: {}\nstorage: {}",
                plan.rel,
                dt.name,
                class.as_str()
            );
            scrolls.push((coll_coord(series, 5, 2, 1, 1), header));
            let content = match class {
                StorageClass::Text => subset.clone(),
                StorageClass::Binary => libphext::binary::encode_scroll(subset.as_bytes()),
            };
            scrolls.push((coll_coord(series, 5, 2, 1, 2), content));
        }
    }
    {
        let mut lines: Vec<String> = vec![format!("key: paper:{}", paper_slug)];
        lines.push(format!("title: {}", escape_value(&extract_title(root, &plan.rel))));
        if let Some(ident) = first_named(root, "msIdentifier") {
            for c in &ident.children {
                if let Node::Elem(ch) = c {
                    lines.push(format!(
                        "ms-{}: {}",
                        ch.name,
                        escape_value(&collapse_ws(&element_text(ch)))
                    ));
                }
            }
        }
        lines.push(format!("source-path: {}", plan.rel));
        lines.push(format!("source-sha256: {}", plan.sha256));
        if let Some(dt) = &parsed.doctype {
            lines.push(format!("doctype-name: {}", dt.name));
            if let Some(p) = &dt.public_id {
                lines.push(format!("doctype-public-id: {}", escape_value(p)));
            }
            if let Some(s) = &dt.system_id {
                lines.push(format!("doctype-system-id: {}", escape_value(s)));
            }
            if dt.internal_subset.is_some() {
                lines.push(format!(
                    "doctype-subset: {}",
                    coll_coord(series, 5, 2, 1, 2).addr()
                ));
            }
        }
        lines.push("conversion: converted".to_string());
        scrolls.push((meta_coord, lines.join("\n")));
    }

    DocLayout {
        series,
        scrolls,
        seg_scroll,
        seg_owner,
        kept_order,
        owner_kept,
        inline_home,
        meta_coord,
        id_to_key,
        elem_key,
        obj_coord,
    }
}

// ---------------------------------------------------------------------------
// Standoff entry records: everything about an entry except the pinned
// target/refers addresses, which are formatted at assembly time once the
// base edition's checksum (and therefore its pin) exists.

#[derive(Debug, Clone, PartialEq)]
pub enum RefOut {
    Key { kind: String, slug: String },
    Unresolved(String),
    External(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum TargetForm {
    /// The occurrence is a keyed object and its home is the object's own
    /// scroll: address by key (STANDOFF §2.1's preferred form).
    Object { kind: String, slug: String },
    /// Coordinate form with a half-open scalar span.
    At { coord: C9, start: usize, end: usize },
}

#[derive(Debug, Clone)]
pub struct EntryRec {
    pub kind: &'static str, // tei-element | tei-comment | tei-pi
    pub form: TargetForm,
    pub hash: String,
    pub text: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub tei_element: Option<String>,
    pub tei_ns: Option<String>,
    pub pi_target: Option<String>,
    /// (rendered name, raw value) in document order, xmlns excluded.
    pub attrs: Vec<(String, String)>,
    pub refs: Vec<RefOut>,
    pub body: String,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RefCounts {
    pub resolved: usize,
    pub unresolved: usize,
    pub external: usize,
}

/// The §2.3 survival kit over one scroll's full stored text.
fn kit(
    scroll_text: &str,
    start: usize,
    end: usize,
) -> (String, String, Option<String>, Option<String>) {
    let chars: Vec<char> = scroll_text.chars().collect();
    let start = start.min(chars.len());
    let end = end.min(chars.len()).max(start);
    let span: String = chars[start..end].iter().collect();
    let hash = phext::checksum(&span);
    let before = if start == 0 {
        None
    } else {
        Some(chars[start.saturating_sub(80)..start].iter().collect())
    };
    let after = if end >= chars.len() {
        None
    } else {
        Some(chars[end..(end + 80).min(chars.len())].iter().collect())
    };
    (hash, span, before, after)
}

/// Render an attribute's qualified name for an `attr-` header line:
/// namespaced names render as `{<namespace-uri>}<local>` (profile §4);
/// the prefix resolves against the xmlns declarations in scope, with
/// `xml` predefined. An unresolvable prefix (undeclared — malformed
/// input) renders as written.
pub fn render_attr_name(qname: &str, scope: &HashMap<String, String>) -> String {
    match qname.split_once(':') {
        Some((prefix, local)) => {
            let ns = if prefix == "xml" {
                Some("http://www.w3.org/XML/1998/namespace".to_string())
            } else {
                scope.get(prefix).cloned()
            };
            match ns {
                Some(uri) => format!("{{{}}}{}", uri, local),
                None => qname.to_string(),
            }
        }
        None => qname.to_string(),
    }
}

struct EntryBuilder<'a> {
    plan: &'a FilePlan,
    layout: &'a DocLayout,
    flat: Flat<'a>,
    mark_pos: HashMap<(usize, usize), (Option<usize>, usize, Option<usize>)>,
    scroll_texts: HashMap<C9, &'a str>,
    out: Vec<EntryRec>,
    counts: RefCounts,
}

impl<'a> EntryBuilder<'a> {
    fn prev_kept_le(&self, raw: usize) -> Option<&'a SegScroll> {
        self.layout
            .kept_order
            .iter()
            .rev()
            .find(|&&r| r <= raw)
            .and_then(|r| self.layout.seg_scroll.get(&r))
    }
    fn next_kept_gt(&self, raw: usize) -> Option<&'a SegScroll> {
        self.layout
            .kept_order
            .iter()
            .find(|&&r| r > raw)
            .and_then(|r| self.layout.seg_scroll.get(&r))
    }

    /// Anchor point for a comment/PI mark (profile §3.3).
    fn mark_home(&self, seg: Option<usize>, offset: usize, after: Option<usize>) -> (C9, usize) {
        if let Some(raw) = seg {
            if let Some(ss) = self.layout.seg_scroll.get(&raw) {
                return (ss.coord, ss.prefix + offset);
            }
            // the mark's segment was dropped by the keep rule: the mark
            // sat in formatting whitespace between surviving segments
            if let Some(ss) = self.prev_kept_le(raw) {
                return (ss.coord, ss.total);
            }
            if let Some(ss) = self.next_kept_gt(raw) {
                return (ss.coord, ss.prefix);
            }
            return (self.layout.meta_coord, 0);
        }
        if let Some(a) = after {
            if let Some(ss) = self.prev_kept_le(a) {
                return (ss.coord, ss.total);
            }
            if let Some(ss) = self.next_kept_gt(a) {
                return (ss.coord, ss.prefix);
            }
        }
        (self.layout.meta_coord, 0)
    }

    fn mark_entry(&self, node: &Node, coord: C9, at: usize) -> EntryRec {
        let scroll_text = self.scroll_texts.get(&coord).copied().unwrap_or("");
        let (hash, text, before, after) = kit(scroll_text, at, at);
        let (kind, pi_target, body) = match node {
            Node::Comment(c) => ("tei-comment", None, c.clone()),
            Node::Pi { target, data } => ("tei-pi", Some(target.clone()), data.clone()),
            _ => unreachable!("mark_entry on a non-mark node"),
        };
        EntryRec {
            kind,
            form: TargetForm::At { coord, start: at, end: at },
            hash,
            text,
            before,
            after,
            tei_element: None,
            tei_ns: None,
            pi_target,
            attrs: Vec::new(),
            refs: Vec::new(),
            body,
        }
    }

    fn refs_of(&mut self, el: &Element) -> Vec<RefOut> {
        let mut out = Vec::new();
        for (name, value) in &el.attrs {
            if !POINTING_ATTRS.contains(&name.as_str()) {
                continue;
            }
            for tok in value.split_whitespace() {
                if let Some(frag) = tok.strip_prefix('#') {
                    if !frag.is_empty() {
                        if let Some((k, s)) = self.layout.id_to_key.get(frag) {
                            self.counts.resolved += 1;
                            out.push(RefOut::Key { kind: k.clone(), slug: s.clone() });
                            continue;
                        }
                    }
                    self.counts.unresolved += 1;
                    out.push(RefOut::Unresolved(tok.to_string()));
                } else {
                    self.counts.external += 1;
                    out.push(RefOut::External(tok.to_string()));
                }
            }
        }
        out
    }

    fn element_entry(&mut self, elem: usize, scope: &HashMap<String, String>) -> EntryRec {
        let el = self.flat.nodes[elem];
        let (coord, start, end) = self.layout.home_of(&self.flat, elem);
        // Object form is used for exactly one case: a section occurrence.
        // The section's object scroll is a Body scroll (its heading
        // scroll), and the entry's kit then describes that scroll whole —
        // the anchor denotes the object, not the element's home span.
        // Every other keyed occurrence (bibentry, figure, cited element)
        // anchors by coordinate to its home span; its key still resolves
        // through the object table and refers-to lines.
        let object_form = match self.layout.elem_key.get(&elem) {
            Some((kind, slug)) if kind == "section" => {
                Some((kind.clone(), slug.clone(), self.layout.obj_coord[&elem]))
            }
            _ => None,
        };
        let (form, kit_coord, ks, ke) = match object_form {
            Some((kind, slug, oc)) => {
                let total = self
                    .scroll_texts
                    .get(&oc)
                    .map(|t| t.chars().count())
                    .unwrap_or(0);
                (TargetForm::Object { kind, slug }, oc, 0, total)
            }
            None => (TargetForm::At { coord, start, end }, coord, start, end),
        };
        let scroll_text = self.scroll_texts.get(&kit_coord).copied().unwrap_or("");
        let (hash, text, before, after) = kit(scroll_text, ks, ke);
        let attrs: Vec<(String, String)> = el
            .attrs
            .iter()
            .filter(|(k, _)| k != "xmlns" && !k.starts_with("xmlns:"))
            .map(|(k, v)| (render_attr_name(k, scope), v.clone()))
            .collect();
        let refs = self.refs_of(el);
        EntryRec {
            kind: "tei-element",
            form,
            hash,
            text,
            before,
            after,
            tei_element: Some(el.name.clone()),
            tei_ns: if el.ns != TEI_NS {
                Some(if el.ns.is_empty() { "(none)".to_string() } else { el.ns.clone() })
            } else {
                None
            },
            pi_target: None,
            attrs,
            refs,
            body: self.flat.text[elem].clone(),
        }
    }

    fn walk(&mut self, elem: usize, scope: &HashMap<String, String>) -> Result<(), String> {
        let el = self.flat.nodes[elem];
        let mut scope = scope.clone();
        for (k, v) in &el.attrs {
            if k == "xmlns" {
                scope.insert(String::new(), v.clone());
            } else if let Some(p) = k.strip_prefix("xmlns:") {
                scope.insert(p.to_string(), v.clone());
            }
        }
        let rec = self.element_entry(elem, &scope);
        self.out.push(rec);
        let mut nth = 0usize;
        for child in &el.children {
            match child {
                Node::Elem(c) => {
                    let ci = self.flat.index_of(c);
                    self.walk(ci, &scope)?;
                }
                Node::Text(_) => {}
                Node::Comment(_) | Node::Pi { .. } => {
                    let (seg, offset, after) = self
                        .mark_pos
                        .get(&(elem, nth))
                        .copied()
                        .ok_or_else(|| {
                            format!(
                                "internal: segmentation mark not found ({} / {})",
                                self.plan.rel, elem
                            )
                        })?;
                    let (coord, at) = self.mark_home(seg, offset, after);
                    let rec = self.mark_entry(child, coord, at);
                    self.out.push(rec);
                    nth += 1;
                }
            }
        }
        Ok(())
    }
}

/// Build all standoff entry records for one converted document, in
/// document order (prolog marks, tree traversal, epilog marks).
fn build_entries(
    plan: &FilePlan,
    parsed: &ParsedDocument,
    layout: &DocLayout,
) -> Result<(Vec<EntryRec>, RefCounts), String> {
    let flat = flatten(&parsed.root);
    let seg = segment_document(&parsed.root, &flat);
    let mark_pos: HashMap<(usize, usize), (Option<usize>, usize, Option<usize>)> = seg
        .marks
        .iter()
        .map(|m| ((m.container, m.nth), (m.seg, m.offset, m.after)))
        .collect();
    let scroll_texts: HashMap<C9, &str> =
        layout.scrolls.iter().map(|(c, t)| (*c, t.as_str())).collect();
    let mut b = EntryBuilder {
        plan,
        layout,
        flat,
        mark_pos,
        scroll_texts,
        out: Vec::new(),
        counts: RefCounts::default(),
    };
    for node in &parsed.prolog {
        let rec = b.mark_entry(node, layout.meta_coord, 0);
        b.out.push(rec);
    }
    b.walk(0, &HashMap::new())?;
    if !parsed.epilog.is_empty() {
        let (coord, at) = match layout.kept_order.last() {
            Some(raw) => {
                let ss = &layout.seg_scroll[raw];
                (ss.coord, ss.total)
            }
            None => (layout.meta_coord, 0),
        };
        for node in &parsed.epilog {
            let rec = b.mark_entry(node, coord, at);
            b.out.push(rec);
        }
    }
    Ok((b.out, b.counts))
}

// ---------------------------------------------------------------------------
// Assembly and writers. `assemble_base` and `assemble_standoff` are the
// two writers of the D6 seam: both consume finished per-document layouts
// (plus, for the standoff, the entry records and the base pin).

fn format_entry(
    rec: &EntryRec,
    key_n: usize,
    corpus_slug: &str,
    pin: &str,
    created: &str,
) -> String {
    let addr = |selector: &str| format!("px2:corpus:{}@e:{}#{}", corpus_slug, pin, selector);
    let target = match &rec.form {
        TargetForm::Object { kind, slug } => addr(&format!("{}:{}", kind, slug)),
        TargetForm::At { coord, start, end } => {
            addr(&format!("at:{}@{}..{}", coord.addr(), start, end))
        }
    };
    let mut lines: Vec<String> = vec![
        "@annotation".to_string(),
        format!("kind: {}", rec.kind),
        format!("key: annotation:e-{}", key_n),
        format!("target: {}", target),
        format!("target-hash: xxh3-128:{}", rec.hash),
        format!("target-text: {}", escape_value(&rec.text)),
    ];
    if let Some(b) = &rec.before {
        lines.push(format!("target-before: {}", escape_value(b)));
    }
    if let Some(a) = &rec.after {
        lines.push(format!("target-after: {}", escape_value(a)));
    }
    if let Some(e) = &rec.tei_element {
        lines.push(format!("tei-element: {}", e));
    }
    if let Some(ns) = &rec.tei_ns {
        lines.push(format!("tei-namespace: {}", ns));
    }
    if let Some(t) = &rec.pi_target {
        lines.push(format!("pi-target: {}", t));
    }
    for (name, value) in &rec.attrs {
        lines.push(format!("attr-{}: {}", name, escape_value(value)));
    }
    for r in &rec.refs {
        match r {
            RefOut::Key { kind, slug } => {
                lines.push(format!("refers-to: {}", addr(&format!("{}:{}", kind, slug))))
            }
            RefOut::Unresolved(tok) => lines.push(format!("refers-to-unresolved: {}", tok)),
            RefOut::External(uri) => lines.push(format!("refers-to-external: {}", uri)),
        }
    }
    lines.push("author: teixml-to-mutable".to_string());
    lines.push(format!("produced-by: {}", CONVERTER));
    lines.push(format!("created: {}", created));
    lines.push(String::new());
    lines.push(rec.body.clone());
    lines.join("\n")
}

struct AssembledBase {
    map: HashMap<phext::Coordinate, String>,
    checksum: String,
}

fn assemble_base(
    corpus_slug: &str,
    plans: &[FilePlan],
    layouts: &[DocLayout],
    registry: &KeyRegistry,
    externals: &HashSet<String>,
    created: &str,
) -> AssembledBase {
    let mut map: HashMap<phext::Coordinate, String> = HashMap::new();
    for layout in layouts {
        for (coord, text) in &layout.scrolls {
            map.insert(coord.phext(), text.clone());
        }
    }
    // object table: one index scroll per kind present, chapters in
    // KIND_ORDER sequence starting at 2; ledger right after.
    let mut by_kind: HashMap<&str, Vec<(&String, &C9)>> = HashMap::new();
    for (kind, slug, coord) in &registry.minted {
        by_kind.entry(kind.as_str()).or_default().push((slug, coord));
    }
    let kinds_present: Vec<&str> =
        KIND_ORDER.iter().cloned().filter(|k| by_kind.contains_key(k)).collect();
    let mut manifest_lines: Vec<String> = vec![
        format!("corpus: {}", corpus_slug),
        "kind: tei-corpus".to_string(),
        format!("tei-profile: {}", PROFILE_VERSION),
        format!("converter: {}", CONVERTER),
        format!("created: {}", created),
        format!(
            "documents: {}",
            plans.iter().filter(|p| p.error.is_none()).count()
        ),
        format!(
            "failures: {}",
            plans.iter().filter(|p| p.error.is_some()).count()
        ),
    ];
    for (i, kind) in kinds_present.iter().enumerate() {
        let coord = coll_coord(1, 6, (i + 2) as u32, 1, 1);
        let mut entries = by_kind[kind].clone();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let text = entries
            .iter()
            .map(|(slug, c)| format!("{}:{} -> {}", kind, slug, c.addr()))
            .collect::<Vec<_>>()
            .join("\n");
        map.insert(coord.phext(), text);
        manifest_lines.push(format!("object-index: {} {}", kind, coord.addr()));
    }
    let ledger_coord = coll_coord(1, 6, (kinds_present.len() + 2) as u32, 1, 1);
    let mut ledger_lines = vec![format!(
        "ledger: key minting record — {} keys",
        registry.minted.len()
    )];
    for (kind, slug, coord) in &registry.minted {
        ledger_lines.push(format!("minted: {}:{} -> {}", kind, slug, coord.addr()));
    }
    map.insert(ledger_coord.phext(), ledger_lines.join("\n"));
    manifest_lines.push(format!("object-ledger: {}", ledger_coord.addr()));
    let mut ext: Vec<&String> = externals.iter().collect();
    ext.sort();
    for url in ext {
        manifest_lines.push(format!("external: {}", url));
    }
    map.insert(manifest_coord().phext(), manifest_lines.join("\n"));
    let checksum = edition_checksum(&map, manifest_coord());
    let manifest = map.get_mut(&manifest_coord().phext()).unwrap();
    manifest.push_str(&format!("\nchecksum: xxh3-128:{}", checksum));
    AssembledBase { map, checksum }
}

struct AssembledStandoff {
    map: HashMap<phext::Coordinate, String>,
}

#[allow(clippy::too_many_arguments)]
fn assemble_standoff(
    corpus_slug: &str,
    pin: &str,
    doc_entries: &[(u32, Vec<EntryRec>)],
    plans: &[FilePlan],
    layouts: &[DocLayout],
    created: &str,
) -> AssembledStandoff {
    let mut map: HashMap<phext::Coordinate, String> = HashMap::new();
    let mut n = 0usize;
    let mut shard_lines: Vec<(u32, String)> = Vec::new();
    for (series, entries) in doc_entries {
        for (k, rec) in entries.iter().enumerate() {
            n += 1;
            let coord = C9::new((1, 1, 1), (1, 1, 1), (*series, 1, (k + 1) as u32));
            map.insert(coord.phext(), format_entry(rec, n, corpus_slug, pin, created));
            shard_lines.push((*series, format!("annotation:e-{} -> {}", n, coord.addr())));
        }
    }
    // per-document index shards in the standoff's Collection 6
    let mut shards: HashMap<u32, Vec<String>> = HashMap::new();
    for (series, line) in shard_lines {
        shards.entry(series).or_default().push(line);
    }
    for (series, lines) in shards {
        map.insert(coll_coord(series, 6, 1, 1, 1).phext(), lines.join("\n"));
    }
    // events ledger in the standoff's Collection 5
    let mut ledger = vec![format!("events: {}", n)];
    for (plan, layout) in plans.iter().zip(layouts.iter()) {
        match &plan.error {
            None => {
                let count = doc_entries
                    .iter()
                    .find(|(s, _)| *s == layout.series)
                    .map(|(_, e)| e.len())
                    .unwrap_or(0);
                ledger.push(format!(
                    "converted: {} series {} entries {}",
                    plan.rel, layout.series, count
                ));
            }
            Some(err) => {
                ledger.push(format!(
                    "failed: {} — {}",
                    plan.rel,
                    sanitize_line(err)
                ));
            }
        }
    }
    map.insert(coll_coord(1, 5, 1, 1, 1).phext(), ledger.join("\n"));
    let meta = vec![
        format!("standoff-of: px2:corpus:{}", corpus_slug),
        format!("standoff-profile: {}", PROFILE_VERSION),
        format!("converter: {}", CONVERTER),
        format!("created: {}", created),
        format!("entries: {}", n),
    ];
    map.insert(standoff_meta_coord().phext(), meta.join("\n"));
    let checksum = edition_checksum(&map, standoff_meta_coord());
    let m = map.get_mut(&standoff_meta_coord().phext()).unwrap();
    m.push_str(&format!("\nchecksum: xxh3-128:{}", checksum));
    AssembledStandoff { map }
}

// ---------------------------------------------------------------------------
// Export driver

#[derive(Debug)]
pub struct PhexturaFileEntry {
    pub rel: String,
    pub series: u32,
    pub error: Option<String>,
    pub entries: usize,
    pub scrolls: usize,
}

#[derive(Debug)]
pub struct PhexturaSummary {
    pub name: String,
    pub slug: String,
    pub entries: Vec<PhexturaFileEntry>,
    pub documents: usize,
    pub base_path: PathBuf,
    pub standoff_path: PathBuf,
    pub base_bytes: u64,
    pub standoff_bytes: u64,
    pub base_scrolls: usize,
    pub standoff_scrolls: usize,
    pub total_entries: usize,
    pub entries_by_kind: Vec<(String, usize)>,
    pub refs: RefCounts,
    pub externals: usize,
    pub pin: String,
    /// D6 ("Both"): the `cavern.phext` PhextVFS image, when emitted.
    pub vfs_path: Option<PathBuf>,
    pub vfs_bytes: u64,
    pub vfs_scrolls: usize,
}

fn collect_ids_and_cited(root: &Element, ids: &mut HashSet<String>, cited: &mut HashSet<String>) {
    let mut stack: Vec<&Element> = vec![root];
    while let Some(el) = stack.pop() {
        for (k, v) in &el.attrs {
            if k == "xml:id" {
                ids.insert(v.clone());
            }
            if POINTING_ATTRS.contains(&k.as_str()) {
                for tok in v.split_whitespace() {
                    if let Some(frag) = tok.strip_prefix('#') {
                        if !frag.is_empty() {
                            cited.insert(frag.to_string());
                        }
                    }
                }
            }
        }
        for c in &el.children {
            if let Node::Elem(e) = c {
                stack.push(e);
            }
        }
    }
}

pub fn export_phextura(dir: &Path, out_dir: &Path) -> Result<PhexturaSummary, String> {
    export_phextura_opts(dir, out_dir, true)
}

/// As `export_phextura`; `emit_vfs` controls the D6 PhextVFS image
/// (`cavern.phext`), a third consumer of the assembled pair — the corpus
/// and standoff writers are untouched either way (the D6 seam).
pub fn export_phextura_opts(
    dir: &Path,
    out_dir: &Path,
    emit_vfs: bool,
) -> Result<PhexturaSummary, String> {
    let files = collect_xml_files(dir)?;
    let name = dir
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "corpus".to_string());
    let slug = slugify(&name);
    let created = iso_now();

    // ---- pass A: scan, hash, classify, parse, collect ids/cited sets
    let mut plans: Vec<FilePlan> = Vec::new();
    let mut sources: Vec<Vec<u8>> = Vec::new();
    for path in &files {
        let rel = rel_of(dir, path);
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        let class = classify(&bytes);
        let mut plan = FilePlan {
            rel,
            sha256: sha256_hex(&bytes),
            size: bytes.len(),
            class,
            error: None,
            ids: HashSet::new(),
            cited: HashSet::new(),
        };
        match class {
            StorageClass::Binary => {
                plan.error = Some(
                    "stored as binary (bytes are not valid UTF-8/ASCII or contain phext break bytes); not element-parsed"
                        .to_string(),
                );
            }
            StorageClass::Text => match parse_xml_full(&bytes) {
                Ok(doc) => collect_ids_and_cited(&doc.root, &mut plan.ids, &mut plan.cited),
                Err(e) => plan.error = Some(e),
            },
        }
        plans.push(plan);
        sources.push(bytes);
    }

    // ---- pass B: per-document layouts + entry records
    let mut registry = KeyRegistry::default();
    let mut externals: HashSet<String> = HashSet::new();
    let mut layouts: Vec<DocLayout> = Vec::new();
    let mut doc_entries: Vec<(u32, Vec<EntryRec>)> = Vec::new();
    let mut total_refs = RefCounts::default();
    let mut kind_counts: HashMap<&'static str, usize> = HashMap::new();
    for (i, plan) in plans.iter().enumerate() {
        let series = (i + 2) as u32;
        let bytes = &sources[i];
        if plan.error.is_some() {
            layouts.push(failure_layout(plan, series, bytes));
            continue;
        }
        let parsed = match parse_xml_full(bytes) {
            Ok(p) => p,
            Err(e) => {
                // pass A parsed this file; a divergent failure here is a
                // hard error, never a silent reclassification
                return Err(format!("pass B parse diverged for {}: {}", plan.rel, e));
            }
        };
        let layout = build_layout(plan, &parsed, bytes, series, &mut registry, &mut externals);
        let (recs, counts) = build_entries(plan, &parsed, &layout)?;
        total_refs.resolved += counts.resolved;
        total_refs.unresolved += counts.unresolved;
        total_refs.external += counts.external;
        for r in &recs {
            *kind_counts.entry(r.kind).or_default() += 1;
        }
        layouts.push(layout);
        doc_entries.push((series, recs));
    }

    // ---- assemble, write
    let base = assemble_base(&slug, &plans, &layouts, &registry, &externals, &created);
    let pin = base.checksum[..16].to_string();
    let standoff = assemble_standoff(&slug, &pin, &doc_entries, &plans, &layouts, &created);
    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("create {}: {}", out_dir.display(), e))?;
    let base_path = out_dir.join(format!("{}.phext", name));
    let standoff_path = out_dir.join(format!("{}.standoff.phext", name));
    let base_bytes = canonical_bytes(&base.map);
    let standoff_bytes = canonical_bytes(&standoff.map);
    std::fs::write(&base_path, &base_bytes)
        .map_err(|e| format!("write {}: {}", base_path.display(), e))?;
    std::fs::write(&standoff_path, &standoff_bytes)
        .map_err(|e| format!("write {}: {}", standoff_path.display(), e))?;
    // D6: the PhextVFS image wraps the pair's exact bytes as its files
    // (VFS paths /<name>.phext and /<name>.standoff.phext).
    let (vfs_path, vfs_bytes, vfs_scrolls) = if emit_vfs {
        let base_name = base_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let standoff_name = standoff_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let (image, info) = crate::vfs::build_cavern_image(&[
            (base_name.as_str(), &base_bytes),
            (standoff_name.as_str(), &standoff_bytes),
        ]);
        let path = out_dir.join("cavern.phext");
        std::fs::write(&path, &image)
            .map_err(|e| format!("write {}: {}", path.display(), e))?;
        (Some(path), info.bytes as u64, info.scrolls)
    } else {
        (None, 0, 0)
    };
    let failures_path = out_dir.join(format!("{}.failures.txt", name));
    let mut failure_text = String::new();
    for plan in plans.iter().filter(|p| p.error.is_some()) {
        failure_text.push_str(&format!("{}\t{}\n", plan.rel, plan.error.as_deref().unwrap_or("")));
    }
    std::fs::write(&failures_path, failure_text)
        .map_err(|e| format!("write {}: {}", failures_path.display(), e))?;

    let mut entries_out: Vec<PhexturaFileEntry> = Vec::new();
    for (i, plan) in plans.iter().enumerate() {
        let series = (i + 2) as u32;
        let count = doc_entries
            .iter()
            .find(|(s, _)| *s == series)
            .map(|(_, e)| e.len())
            .unwrap_or(0);
        entries_out.push(PhexturaFileEntry {
            rel: plan.rel.clone(),
            series,
            error: plan.error.clone(),
            entries: count,
            scrolls: layouts[i].scrolls.len(),
        });
    }
    let mut entries_by_kind: Vec<(String, usize)> =
        kind_counts.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    entries_by_kind.sort();
    Ok(PhexturaSummary {
        name,
        slug,
        entries: entries_out,
        documents: plans.iter().filter(|p| p.error.is_none()).count(),
        base_path,
        standoff_path,
        base_bytes: base_bytes.len() as u64,
        standoff_bytes: standoff_bytes.len() as u64,
        base_scrolls: base.map.len(),
        standoff_scrolls: standoff.map.len(),
        total_entries: doc_entries.iter().map(|(_, e)| e.len()).sum(),
        entries_by_kind,
        refs: total_refs,
        externals: externals.len(),
        pin,
        vfs_path,
        vfs_bytes,
        vfs_scrolls,
    })
}

// ---------------------------------------------------------------------------
// Reading the pair back: scroll parsing shared by the validator, the
// reconstruction checker, and the re-location harness. These readers are
// deliberately independent of the writers above.

/// A scroll split into role line, header lines, and body (text after the
/// first blank line; header-only scrolls have an empty body).
pub struct ScrollParts {
    pub role: Option<String>,
    pub lines: Vec<(String, String)>,
    pub body: String,
}

pub fn split_scroll(text: &str) -> ScrollParts {
    let (head, body) = match text.find("\n\n") {
        Some(i) => (&text[..i], text[i + 2..].to_string()),
        None => (text, String::new()),
    };
    let mut role = None;
    let mut lines = Vec::new();
    for (i, line) in head.split('\n').enumerate() {
        if i == 0 && line.starts_with('@') {
            role = Some(line.to_string());
            continue;
        }
        if line.is_empty() {
            continue;
        }
        match line.split_once(": ") {
            Some((k, v)) => lines.push((k.to_string(), v.to_string())),
            None if line.ends_with(':') => {
                lines.push((line[..line.len() - 1].to_string(), String::new()))
            }
            None => lines.push((line.to_string(), String::new())),
        }
    }
    ScrollParts { role, lines, body }
}

pub fn line_of<'a>(lines: &'a [(String, String)], name: &str) -> Option<&'a str> {
    lines.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

pub fn lines_of<'a>(lines: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    lines.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
}

pub fn load_map(path: &Path) -> Result<HashMap<C9, String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("read {}: {}", path.display(), e))?;
    let mut out = HashMap::new();
    for (c, s) in phext::explode(&text) {
        let key = C9::parse(&c.to_string())
            .ok_or_else(|| format!("unparseable coordinate {}", c))?;
        out.insert(key, s);
    }
    Ok(out)
}

fn to_phext_map(map: &HashMap<C9, String>) -> HashMap<phext::Coordinate, String> {
    map.iter().map(|(c, s)| (c.phext(), s.clone())).collect()
}

/// (kind, slug) -> coord, from the base's key lines and minting ledger.
fn key_records(
    map: &HashMap<C9, String>,
    failures: &mut Vec<String>,
) -> HashMap<(String, String), C9> {
    let mut out: HashMap<(String, String), C9> = HashMap::new();
    let mut record = |kind: &str, slug: &str, coord: C9, failures: &mut Vec<String>| {
        let key = (kind.to_string(), slug.to_string());
        if let Some(prev) = out.get(&key) {
            if *prev != coord {
                failures.push(format!(
                    "key {}:{} recorded at both {} and {}",
                    kind,
                    slug,
                    prev.addr(),
                    coord.addr()
                ));
            }
        }
        out.insert(key, coord);
    };
    for (coord, text) in map {
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("key: ") {
                if let Some((kind, slug)) = v.split_once(':') {
                    record(kind, slug, *coord, failures);
                }
            }
        }
    }
    if let Some(manifest) = map.get(&manifest_coord()) {
        let parts = split_scroll(manifest);
        if let Some(addr) = line_of(&parts.lines, "object-ledger") {
            if let Some(lc) = C9::parse(addr) {
                if let Some(ledger) = map.get(&lc) {
                    for line in ledger.lines() {
                        if let Some(rest) = line.strip_prefix("minted: ") {
                            if let Some((ks, c)) = rest.split_once(" -> ") {
                                if let (Some((kind, slug)), Some(coord)) =
                                    (ks.split_once(':'), C9::parse(c))
                                {
                                    record(kind, slug, coord, failures);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// The shipped object-table index: (kind, slug) -> coord, read from the
/// index scrolls the manifest declares.
fn shipped_index(
    map: &HashMap<C9, String>,
) -> HashMap<(String, String), C9> {
    let mut out = HashMap::new();
    if let Some(manifest) = map.get(&manifest_coord()) {
        let parts = split_scroll(manifest);
        for v in lines_of(&parts.lines, "object-index") {
            if let Some((kind, addr)) = v.split_once(' ') {
                if let Some(coord) = C9::parse(addr) {
                    if let Some(text) = map.get(&coord) {
                        for line in text.lines() {
                            if let Some((ks, c)) = line.split_once(" -> ") {
                                if let (Some((k, slug)), Some(cc)) =
                                    (ks.split_once(':'), C9::parse(c))
                                {
                                    if k == kind {
                                        out.insert((k.to_string(), slug.to_string()), cc);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct TargetAddr {
    pub slug: String,
    pub pin: String,
    pub kind: Option<String>,
    pub key_slug: Option<String>,
    pub at: Option<(C9, usize, usize)>,
}

pub fn parse_target(addr: &str) -> Result<TargetAddr, String> {
    let rest = addr
        .strip_prefix("px2:corpus:")
        .ok_or_else(|| format!("target is not a px2 corpus address: {}", addr))?;
    let (slug, rest) = rest.split_once("@e:").ok_or("target missing @e:")?;
    let (pin, selector) = rest.split_once('#').ok_or("target missing #")?;
    if let Some(a) = selector.strip_prefix("at:") {
        let (coord_s, span) = a.split_once('@').ok_or("at: selector missing span")?;
        let coord = C9::parse(coord_s).ok_or("at: selector bad coordinate")?;
        let (s, e) = span.split_once("..").ok_or("at: selector bad span")?;
        let start: usize = s.parse().map_err(|_| "at: selector bad span start")?;
        let end: usize = e.parse().map_err(|_| "at: selector bad span end")?;
        Ok(TargetAddr {
            slug: slug.to_string(),
            pin: pin.to_string(),
            kind: None,
            key_slug: None,
            at: Some((coord, start, end)),
        })
    } else {
        let (kind, kslug) = selector.split_once(':').ok_or("bad key selector")?;
        Ok(TargetAddr {
            slug: slug.to_string(),
            pin: pin.to_string(),
            kind: Some(kind.to_string()),
            key_slug: Some(kslug.to_string()),
            at: None,
        })
    }
}

#[derive(Debug)]
pub struct ParsedEntry {
    pub coord: C9,
    pub kind: String,
    pub key_n: usize,
    pub target: TargetAddr,
    pub hash: String,
    pub text: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub tei_element: Option<String>,
    pub tei_ns: Option<String>,
    pub pi_target: Option<String>,
    pub attrs: Vec<(String, String)>,
    pub refers: Vec<String>,
    pub refers_unresolved: Vec<String>,
    pub refers_external: Vec<String>,
    pub body: String,
}

pub fn parse_entry(coord: C9, text: &str) -> Result<ParsedEntry, String> {
    let parts = split_scroll(text);
    if parts.role.as_deref() != Some("@annotation") {
        return Err(format!("scroll {} is not an @annotation entry", coord.addr()));
    }
    let kind = line_of(&parts.lines, "kind")
        .ok_or("entry missing kind")?
        .to_string();
    let key = line_of(&parts.lines, "key").ok_or("entry missing key")?;
    let key_n: usize = key
        .strip_prefix("annotation:e-")
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("entry key not an annotation key: {}", key))?;
    let target_raw = line_of(&parts.lines, "target").ok_or("entry missing target")?;
    let target = parse_target(target_raw)?;
    let hash = line_of(&parts.lines, "target-hash")
        .ok_or("entry missing target-hash")?
        .strip_prefix("xxh3-128:")
        .ok_or("target-hash not xxh3-128")?
        .to_string();
    let unesc = |name: &str| -> Result<Option<String>, String> {
        match line_of(&parts.lines, name) {
            Some(v) => Ok(Some(unescape_value(v)?)),
            None => Ok(None),
        }
    };
    let text_v = unesc("target-text")?.ok_or("entry missing target-text")?;
    let mut attrs = Vec::new();
    for (k, v) in &parts.lines {
        if let Some(name) = k.strip_prefix("attr-") {
            attrs.push((name.to_string(), unescape_value(v)?));
        }
    }
    if line_of(&parts.lines, "produced-by").is_none() {
        return Err("machine entry missing produced-by".into());
    }
    Ok(ParsedEntry {
        coord,
        kind,
        key_n,
        target,
        hash,
        text: text_v,
        before: unesc("target-before")?,
        after: unesc("target-after")?,
        tei_element: line_of(&parts.lines, "tei-element").map(|s| s.to_string()),
        tei_ns: line_of(&parts.lines, "tei-namespace").map(|s| s.to_string()),
        pi_target: line_of(&parts.lines, "pi-target").map(|s| s.to_string()),
        attrs,
        refers: lines_of(&parts.lines, "refers-to").iter().map(|s| s.to_string()).collect(),
        refers_unresolved: lines_of(&parts.lines, "refers-to-unresolved")
            .iter()
            .map(|s| s.to_string())
            .collect(),
        refers_external: lines_of(&parts.lines, "refers-to-external")
            .iter()
            .map(|s| s.to_string())
            .collect(),
        body: parts.body,
    })
}

/// All standoff entries, sorted into minting order (series, then scroll).
pub fn load_entries(
    standoff: &HashMap<C9, String>,
) -> Result<Vec<ParsedEntry>, String> {
    let mut coords: Vec<C9> = standoff
        .keys()
        .filter(|c| c.z == (1, 1, 1) && c.y == (1, 1, 1))
        .copied()
        .collect();
    coords.sort_by_key(|c| (c.x.0, c.x.2));
    let mut out = Vec::with_capacity(coords.len());
    for c in coords {
        out.push(parse_entry(c, &standoff[&c])?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// DESIGN §7 validation over an emitted pair

#[derive(Debug, Default)]
pub struct ValidateReport {
    pub ok: bool,
    pub failures: Vec<String>,
    pub base_scrolls: usize,
    pub standoff_scrolls: usize,
    pub base_checksum_ok: bool,
    pub standoff_checksum_ok: bool,
    pub keys_indexed: usize,
    pub entries: usize,
    pub media_headers: usize,
    pub externals_declared: usize,
    pub bare_coords_in_prose: usize,
    pub resolvable_bare_coords: usize,
}

fn scan_bare_coords(text: &str, map: &HashMap<C9, String>) -> (usize, usize) {
    let bytes = text.as_bytes();
    let mut found = 0usize;
    let mut resolvable = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_digit() || bytes[i] == b'.' || bytes[i] == b'/')
            {
                i += 1;
            }
            let tok = &text[start..i];
            if let Some(c) = C9::parse(tok) {
                if c.addr() == tok {
                    found += 1;
                    if map.contains_key(&c) {
                        resolvable += 1;
                    }
                }
            }
        } else {
            i += 1;
        }
    }
    (found, resolvable)
}

pub fn validate_pair(base_path: &Path, standoff_path: &Path) -> Result<ValidateReport, String> {
    let base = load_map(base_path)?;
    let standoff = load_map(standoff_path)?;
    let mut rep = ValidateReport {
        base_scrolls: base.len(),
        standoff_scrolls: standoff.len(),
        ..Default::default()
    };
    let fail = |rep: &mut ValidateReport, msg: String| {
        if rep.failures.len() < 100 {
            rep.failures.push(msg);
        }
    };
    // --- base manifest + checksum
    let manifest_text = match base.get(&manifest_coord()) {
        Some(t) => t.clone(),
        None => {
            fail(&mut rep, "base manifest scroll missing".into());
            rep.ok = false;
            return Ok(rep);
        }
    };
    let manifest = split_scroll(&manifest_text);
    let slug = line_of(&manifest.lines, "corpus").unwrap_or("").to_string();
    let declared_checksum = line_of(&manifest.lines, "checksum")
        .and_then(|v| v.strip_prefix("xxh3-128:"))
        .unwrap_or("")
        .to_string();
    let recomputed = edition_checksum(&to_phext_map(&base), manifest_coord());
    rep.base_checksum_ok = recomputed == declared_checksum;
    if !rep.base_checksum_ok {
        fail(&mut rep, "base manifest checksum does not recompute".into());
    }
    let pin = recomputed.get(..16).unwrap_or("").to_string();
    // --- object table rebuild
    let records = key_records(&base, &mut rep.failures);
    rep.keys_indexed = records.len();
    let index_lines = lines_of(&manifest.lines, "object-index");
    let mut kinds_in_manifest: HashSet<String> = HashSet::new();
    for v in &index_lines {
        if let Some((kind, addr)) = v.split_once(' ') {
            kinds_in_manifest.insert(kind.to_string());
            let coord = match C9::parse(addr) {
                Some(c) => c,
                None => {
                    fail(&mut rep, format!("object-index bad address {}", addr));
                    continue;
                }
            };
            let mut mine: Vec<(&String, &C9)> = records
                .iter()
                .filter(|((k, _), _)| k == kind)
                .map(|((_, s), c)| (s, c))
                .collect();
            mine.sort_by(|a, b| a.0.cmp(b.0));
            let rebuilt = mine
                .iter()
                .map(|(s, c)| format!("{}:{} -> {}", kind, s, c.addr()))
                .collect::<Vec<_>>()
                .join("\n");
            match base.get(&coord) {
                Some(shipped) if *shipped == rebuilt => {}
                Some(_) => fail(
                    &mut rep,
                    format!("object index for {} does not rebuild byte-for-byte", kind),
                ),
                None => fail(&mut rep, format!("object index scroll {} missing", addr)),
            }
        }
    }
    for kind in KIND_ORDER.iter() {
        let has_records = records.keys().any(|(k, _)| k.as_str() == *kind);
        if has_records && !kinds_in_manifest.contains(*kind) {
            fail(&mut rep, format!("kind {} has keys but no index scroll", kind));
        }
    }
    // --- closure: every Collection 3 url is a declared external
    let externals: HashSet<&str> = lines_of(&manifest.lines, "external").into_iter().collect();
    rep.externals_declared = externals.len();
    for (coord, text) in &base {
        if coord.y.0 == 3 {
            rep.media_headers += 1;
            let parts = split_scroll(text);
            match line_of(&parts.lines, "url") {
                Some(url) if externals.contains(url) => {}
                Some(url) => fail(
                    &mut rep,
                    format!("media header {} names undeclared external {}", coord.addr(), url),
                ),
                None => fail(&mut rep, format!("media header {} has no url", coord.addr())),
            }
        }
    }
    // --- bare coordinates in Body prose
    for (coord, text) in &base {
        if coord.y.0 == 1 && coord.z.2 >= 2 {
            let parts = split_scroll(text);
            let (f, r) = scan_bare_coords(&parts.body, &base);
            rep.bare_coords_in_prose += f;
            rep.resolvable_bare_coords += r;
        }
    }
    if rep.resolvable_bare_coords > 0 {
        let n = rep.resolvable_bare_coords;
        fail(
            &mut rep,
            format!("{} resolvable bare coordinates appear in base prose", n),
        );
    }
    // --- standoff metadata + checksum + pins + entry grammar
    match standoff.get(&standoff_meta_coord()) {
        Some(meta_text) => {
            let meta = split_scroll(meta_text);
            let want = format!("px2:corpus:{}", slug);
            if line_of(&meta.lines, "standoff-of") != Some(want.as_str()) {
                fail(&mut rep, "standoff-of does not name the base corpus".into());
            }
            if line_of(&meta.lines, "standoff-profile") != Some(PROFILE_VERSION) {
                fail(&mut rep, "standoff-profile mismatch".into());
            }
            let declared = line_of(&meta.lines, "checksum")
                .and_then(|v| v.strip_prefix("xxh3-128:"))
                .unwrap_or("")
                .to_string();
            let recomputed_s = edition_checksum(&to_phext_map(&standoff), standoff_meta_coord());
            rep.standoff_checksum_ok = recomputed_s == declared;
            if !rep.standoff_checksum_ok {
                fail(&mut rep, "standoff checksum does not recompute".into());
            }
        }
        None => fail(&mut rep, "standoff metadata scroll missing".into()),
    }
    let entries = match load_entries(&standoff) {
        Ok(e) => e,
        Err(e) => {
            fail(&mut rep, format!("entry parse: {}", e));
            Vec::new()
        }
    };
    rep.entries = entries.len();
    for (i, e) in entries.iter().enumerate() {
        if e.key_n != i + 1 {
            fail(
                &mut rep,
                format!("entry keys not sequential at position {} (saw e-{})", i + 1, e.key_n),
            );
            break;
        }
        if e.target.pin != pin {
            fail(&mut rep, format!("entry e-{} pins a different edition", e.key_n));
            break;
        }
        if e.target.slug != slug {
            fail(&mut rep, format!("entry e-{} targets a different corpus", e.key_n));
            break;
        }
        match &e.target.at {
            Some((coord, _, _)) => {
                if !base.contains_key(coord) {
                    fail(
                        &mut rep,
                        format!("entry e-{} targets absent scroll {}", e.key_n, coord.addr()),
                    );
                }
            }
            None => {
                let key = (
                    e.target.kind.clone().unwrap_or_default(),
                    e.target.key_slug.clone().unwrap_or_default(),
                );
                if !records.contains_key(&key) {
                    fail(
                        &mut rep,
                        format!("entry e-{} targets unknown key {}:{}", e.key_n, key.0, key.1),
                    );
                }
            }
        }
    }
    // --- standoff index shards rebuild
    let mut shards: HashMap<u32, Vec<String>> = HashMap::new();
    for e in &entries {
        shards
            .entry(e.coord.x.0)
            .or_default()
            .push(format!("annotation:e-{} -> {}", e.key_n, e.coord.addr()));
    }
    for (series, lines) in &shards {
        let coord = coll_coord(*series, 6, 1, 1, 1);
        let rebuilt = lines.join("\n");
        match standoff.get(&coord) {
            Some(shipped) if *shipped == rebuilt => {}
            _ => fail(
                &mut rep,
                format!("standoff index shard for series {} does not rebuild", series),
            ),
        }
    }
    rep.ok = rep.failures.is_empty();
    Ok(rep)
}

// ---------------------------------------------------------------------------
// Reconstruction checker (SPEC-0.3 T3/T4): from the emitted pair alone,
// prove the conversion is TEI-equivalent to the source XML model — text,
// structure, properties, comments/PIs (D3), references — and that every
// hoisted original is byte-identical to its source file.

#[derive(Debug, Default)]
pub struct ReconReport {
    pub ok: bool,
    pub mismatches: Vec<String>,
    pub mismatch_total: usize,
    pub files: usize,
    pub originals_verified: usize,
    pub segments: usize,
    pub elements: usize,
    pub attributes: usize,
    pub comments: usize,
    pub pis: usize,
    pub doctypes: usize,
    pub refs_resolved: usize,
    pub refs_unresolved: usize,
    pub refs_external: usize,
}

struct ExpectEntry {
    name: String,
    ns_rendered: Option<String>,
    attrs: Vec<(String, String)>,
    body: String,
}

struct ExpectMark {
    kind: &'static str,
    pi_target: Option<String>,
    body: String,
}

fn expect_walk(
    el: &Element,
    flat: &Flat,
    scope: &HashMap<String, String>,
    elems: &mut Vec<ExpectEntry>,
    marks: &mut Vec<ExpectMark>,
) {
    let mut scope = scope.clone();
    for (k, v) in &el.attrs {
        if k == "xmlns" {
            scope.insert(String::new(), v.clone());
        } else if let Some(p) = k.strip_prefix("xmlns:") {
            scope.insert(p.to_string(), v.clone());
        }
    }
    let idx = flat.index_of(el);
    elems.push(ExpectEntry {
        name: el.name.clone(),
        ns_rendered: if el.ns != TEI_NS {
            Some(if el.ns.is_empty() { "(none)".to_string() } else { el.ns.clone() })
        } else {
            None
        },
        attrs: el
            .attrs
            .iter()
            .filter(|(k, _)| k != "xmlns" && !k.starts_with("xmlns:"))
            .map(|(k, v)| (render_attr_name(k, &scope), v.clone()))
            .collect(),
        body: flat.text[idx].clone(),
    });
    for child in &el.children {
        match child {
            Node::Elem(c) => expect_walk(c, flat, &scope, elems, marks),
            Node::Comment(t) => marks.push(ExpectMark {
                kind: "tei-comment",
                pi_target: None,
                body: t.clone(),
            }),
            Node::Pi { target, data } => marks.push(ExpectMark {
                kind: "tei-pi",
                pi_target: Some(target.clone()),
                body: data.clone(),
            }),
            Node::Text(_) => {}
        }
    }
}

fn entry_home(
    e: &ParsedEntry,
    index: &HashMap<(String, String), C9>,
) -> Option<C9> {
    match &e.target.at {
        Some((c, _, _)) => Some(*c),
        None => {
            let kind = e.target.kind.clone()?;
            let slug = e.target.key_slug.clone()?;
            index.get(&(kind, slug)).copied()
        }
    }
}

pub fn check_reconstruction(
    base_path: &Path,
    standoff_path: &Path,
    corpus_dir: &Path,
) -> Result<ReconReport, String> {
    let base = load_map(base_path)?;
    let standoff = load_map(standoff_path)?;
    let index = shipped_index(&base);
    let entries = load_entries(&standoff)?;
    let mut by_series: HashMap<u32, Vec<&ParsedEntry>> = HashMap::new();
    for e in &entries {
        by_series.entry(e.coord.x.0).or_default().push(e);
    }
    let mut rep = ReconReport::default();
    macro_rules! mismatch {
        ($($arg:tt)*) => {
            {
                rep.mismatch_total += 1;
                if rep.mismatches.len() < 100 {
                    rep.mismatches.push(format!($($arg)*));
                }
            }
        };
    }
    // document metadata scrolls: Series >= 2, Collection 6, X = 1.1.1
    let mut series_list: Vec<u32> = base
        .keys()
        .filter(|c| c.z.2 >= 2 && c.y == (6, 1, 1) && c.x == (1, 1, 1))
        .map(|c| c.z.2)
        .collect();
    series_list.sort();
    for series in series_list {
        let meta_coord = coll_coord(series, 6, 1, 1, 1);
        let meta = split_scroll(&base[&meta_coord]);
        let rel = line_of(&meta.lines, "source-path").unwrap_or("").to_string();
        let conversion = line_of(&meta.lines, "conversion").unwrap_or("").to_string();
        rep.files += 1;
        let source = match std::fs::read(corpus_dir.join(&rel)) {
            Ok(b) => b,
            Err(e) => {
                mismatch!("{}: source unreadable: {}", rel, e);
                continue;
            }
        };
        // T4: hoisted original byte-identity (every file, failed or not)
        let header_coord = coll_coord(series, 5, 1, 1, 1);
        match base.get(&header_coord) {
            Some(h) => {
                let hp = split_scroll(h);
                if line_of(&hp.lines, "source-sha256") != Some(sha256_hex(&source).as_str()) {
                    mismatch!("{}: original header sha256 mismatch", rel);
                }
                let storage = line_of(&hp.lines, "storage").unwrap_or("");
                if source.is_empty() {
                    rep.originals_verified += 1;
                } else {
                    match base.get(&coll_coord(series, 5, 1, 1, 2)) {
                        Some(content) => {
                            let bytes = if storage == "binary" {
                                libphext::binary::decode_scroll(content)
                                    .unwrap_or_default()
                            } else {
                                content.as_bytes().to_vec()
                            };
                            if bytes == source {
                                rep.originals_verified += 1;
                            } else {
                                mismatch!("{}: hoisted original bytes differ", rel);
                            }
                        }
                        None => mismatch!("{}: original content scroll missing", rel),
                    }
                }
            }
            None => mismatch!("{}: original header scroll missing", rel),
        }
        let doc_entries: Vec<&ParsedEntry> =
            by_series.get(&series).cloned().unwrap_or_default();
        if conversion.starts_with("failed") {
            if !doc_entries.is_empty() {
                mismatch!("{}: failed document has standoff entries", rel);
            }
            let actually_fails = classify(&source) == StorageClass::Binary
                || parse_xml_full(&source).is_err();
            if !actually_fails {
                mismatch!("{}: marked failed but the source parses", rel);
            }
            continue;
        }
        let parsed = match parse_xml_full(&source) {
            Ok(p) => p,
            Err(e) => {
                mismatch!("{}: source no longer parses: {}", rel, e);
                continue;
            }
        };
        let flat = flatten(&parsed.root);
        let seg = segment_document(&parsed.root, &flat);
        let kept = kept_map(&seg);
        // --- text: Body scroll bodies == kept segment texts, in order
        let mut body_coords: Vec<C9> = base
            .keys()
            .filter(|c| c.z.2 == series && c.y.0 == 1)
            .copied()
            .collect();
        body_coords.sort_by_key(|c| (c.y.2, c.x.0, c.x.1, c.x.2));
        let kept_segs: Vec<&crate::segment::Segment> = seg
            .segments
            .iter()
            .zip(kept.iter())
            .filter(|(_, k)| k.is_some())
            .map(|(s, _)| s)
            .collect();
        if body_coords.len() != kept_segs.len() {
            mismatch!(
                "{}: {} body scrolls vs {} kept segments",
                rel,
                body_coords.len(),
                kept_segs.len()
            );
        }
        for (coord, s) in body_coords.iter().zip(kept_segs.iter()) {
            let parts = split_scroll(&base[coord]);
            if parts.body != s.text {
                mismatch!("{}: segment text differs at {}", rel, coord.addr());
            }
            rep.segments += 1;
        }
        // --- elements + marks from the pair vs the model
        let mut expect_elems: Vec<ExpectEntry> = Vec::new();
        let mut expect_marks: Vec<ExpectMark> = Vec::new();
        for node in &parsed.prolog {
            match node {
                Node::Comment(t) => expect_marks.push(ExpectMark {
                    kind: "tei-comment",
                    pi_target: None,
                    body: t.clone(),
                }),
                Node::Pi { target, data } => expect_marks.push(ExpectMark {
                    kind: "tei-pi",
                    pi_target: Some(target.clone()),
                    body: data.clone(),
                }),
                _ => {}
            }
        }
        expect_walk(&parsed.root, &flat, &HashMap::new(), &mut expect_elems, &mut expect_marks);
        for node in &parsed.epilog {
            match node {
                Node::Comment(t) => expect_marks.push(ExpectMark {
                    kind: "tei-comment",
                    pi_target: None,
                    body: t.clone(),
                }),
                Node::Pi { target, data } => expect_marks.push(ExpectMark {
                    kind: "tei-pi",
                    pi_target: Some(target.clone()),
                    body: data.clone(),
                }),
                _ => {}
            }
        }
        let elem_entries: Vec<&ParsedEntry> =
            doc_entries.iter().filter(|e| e.kind == "tei-element").cloned().collect();
        let mark_entries: Vec<&ParsedEntry> =
            doc_entries.iter().filter(|e| e.kind != "tei-element").cloned().collect();
        if elem_entries.len() != expect_elems.len() {
            mismatch!(
                "{}: {} element entries vs {} model elements",
                rel,
                elem_entries.len(),
                expect_elems.len()
            );
        }
        for (i, (got, want)) in elem_entries.iter().zip(expect_elems.iter()).enumerate() {
            if got.tei_element.as_deref() != Some(want.name.as_str()) {
                mismatch!("{}: element {} name differs", rel, i);
                continue;
            }
            if got.tei_ns != want.ns_rendered {
                mismatch!("{}: element {} namespace differs", rel, i);
            }
            if got.attrs != want.attrs {
                mismatch!("{}: element {} attributes differ", rel, i);
            }
            if got.body != want.body {
                mismatch!("{}: element {} text differs", rel, i);
            }
            rep.elements += 1;
            rep.attributes += want.attrs.len();
        }
        if mark_entries.len() != expect_marks.len() {
            mismatch!(
                "{}: {} comment/PI entries vs {} in the model",
                rel,
                mark_entries.len(),
                expect_marks.len()
            );
        }
        for (got, want) in mark_entries.iter().zip(expect_marks.iter()) {
            if got.kind != want.kind || got.pi_target != want.pi_target || got.body != want.body {
                mismatch!("{}: comment/PI entry differs", rel);
            }
            if want.kind == "tei-comment" {
                rep.comments += 1;
            } else {
                rep.pis += 1;
            }
        }
        // --- references: expected from the model, compared by resolved
        // coordinate (never by slug — the index is the arbiter)
        let mut id_to_elem: HashMap<&str, usize> = HashMap::new();
        for i in 0..flat.len() {
            if let Some((_, id)) = flat.nodes[i].attrs.iter().find(|(k, _)| k == "xml:id") {
                id_to_elem.insert(id.as_str(), i);
            }
        }
        for i in 0..flat.len() {
            let el = flat.nodes[i];
            let entry = match elem_entries.get(i) {
                Some(e) => *e,
                None => break,
            };
            let mut want_keys: Vec<C9> = Vec::new();
            let mut want_unres: Vec<String> = Vec::new();
            let mut want_ext: Vec<String> = Vec::new();
            for (name, value) in &el.attrs {
                if !POINTING_ATTRS.contains(&name.as_str()) {
                    continue;
                }
                for tok in value.split_whitespace() {
                    if let Some(frag) = tok.strip_prefix('#') {
                        match id_to_elem.get(frag) {
                            Some(target_elem) => {
                                match elem_entries
                                    .get(*target_elem)
                                    .and_then(|te| entry_home(te, &index))
                                {
                                    Some(c) => want_keys.push(c),
                                    None => mismatch!(
                                        "{}: reference target entry has no home",
                                        rel
                                    ),
                                }
                                rep.refs_resolved += 1;
                            }
                            None => {
                                want_unres.push(tok.to_string());
                                rep.refs_unresolved += 1;
                            }
                        }
                    } else {
                        want_ext.push(tok.to_string());
                        rep.refs_external += 1;
                    }
                }
            }
            let mut got_keys: Vec<C9> = Vec::new();
            for r in &entry.refers {
                match parse_target(r) {
                    Ok(t) => {
                        let key = (
                            t.kind.clone().unwrap_or_default(),
                            t.key_slug.clone().unwrap_or_default(),
                        );
                        match index.get(&key) {
                            Some(c) => got_keys.push(*c),
                            None => mismatch!("{}: refers-to names unknown key", rel),
                        }
                    }
                    Err(e) => mismatch!("{}: refers-to unparsable: {}", rel, e),
                }
            }
            if got_keys != want_keys {
                mismatch!("{}: element {} resolved references differ", rel, i);
            }
            if entry.refers_unresolved != want_unres {
                mismatch!("{}: element {} unresolved references differ", rel, i);
            }
            if entry.refers_external != want_ext {
                mismatch!("{}: element {} external references differ", rel, i);
            }
        }
        // --- doctype
        match &parsed.doctype {
            Some(dt) => {
                rep.doctypes += 1;
                if line_of(&meta.lines, "doctype-name") != Some(dt.name.as_str()) {
                    mismatch!("{}: doctype-name differs", rel);
                }
                if line_of(&meta.lines, "doctype-public-id") != dt.public_id.as_deref() {
                    mismatch!("{}: doctype-public-id differs", rel);
                }
                if line_of(&meta.lines, "doctype-system-id") != dt.system_id.as_deref() {
                    mismatch!("{}: doctype-system-id differs", rel);
                }
                if let Some(subset) = &dt.internal_subset {
                    let hcoord = coll_coord(series, 5, 2, 1, 1);
                    let storage = base
                        .get(&hcoord)
                        .map(|h| {
                            split_scroll(h)
                                .lines
                                .iter()
                                .find(|(k, _)| k == "storage")
                                .map(|(_, v)| v.clone())
                        })
                        .flatten()
                        .unwrap_or_default();
                    match base.get(&coll_coord(series, 5, 2, 1, 2)) {
                        Some(content) => {
                            let got = if storage == "binary" {
                                libphext::binary::decode_scroll(content)
                                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                                    .unwrap_or_default()
                            } else {
                                content.clone()
                            };
                            if got != *subset {
                                mismatch!("{}: doctype subset differs", rel);
                            }
                        }
                        None => mismatch!("{}: doctype subset scroll missing", rel),
                    }
                }
            }
            None => {
                if line_of(&meta.lines, "doctype-name").is_some() {
                    mismatch!("{}: metadata names a doctype the source lacks", rel);
                }
            }
        }
        // --- bibliography entries
        let mut bib_expect: Vec<String> = Vec::new();
        for i in 0..flat.len() {
            let name = flat.nodes[i].name.as_str();
            if name != "bibl" && name != "biblStruct" {
                continue;
            }
            let mut nested = false;
            let mut p = flat.parent[i];
            while let Some(pi) = p {
                let pn = flat.nodes[pi].name.as_str();
                if pn == "bibl" || pn == "biblStruct" {
                    nested = true;
                    break;
                }
                p = flat.parent[pi];
            }
            if nested {
                continue;
            }
            let t = collapse_ws(&flat.text[i]);
            if !t.is_empty() {
                bib_expect.push(t);
            }
        }
        let mut bib_coords: Vec<C9> = base
            .keys()
            .filter(|c| c.z.2 == series && c.y == (2, 1, 1))
            .copied()
            .collect();
        bib_coords.sort_by_key(|c| c.x.2);
        if bib_coords.len() != bib_expect.len() {
            mismatch!(
                "{}: {} bibentry scrolls vs {} expected",
                rel,
                bib_coords.len(),
                bib_expect.len()
            );
        }
        for (coord, want) in bib_coords.iter().zip(bib_expect.iter()) {
            let parts = split_scroll(&base[coord]);
            match line_of(&parts.lines, "text") {
                Some(v) => match unescape_value(v) {
                    Ok(t) if t == *want => {}
                    _ => mismatch!("{}: bibentry text differs at {}", rel, coord.addr()),
                },
                None => mismatch!("{}: bibentry scroll {} has no text line", rel, coord.addr()),
            }
        }
        // --- media headers vs the model's graphic urls
        let mut want_urls: Vec<String> = Vec::new();
        for i in 0..flat.len() {
            if flat.nodes[i].name == "graphic" {
                if let Some((_, url)) = flat.nodes[i].attrs.iter().find(|(k, _)| k == "url") {
                    want_urls.push(url.clone());
                }
            }
        }
        let mut got_urls: Vec<String> = Vec::new();
        for (coord, text) in &base {
            if coord.z.2 == series && coord.y == (3, 1, 1) {
                let parts = split_scroll(text);
                if let Some(u) = line_of(&parts.lines, "url") {
                    got_urls.push(u.to_string());
                }
            }
        }
        want_urls.sort();
        got_urls.sort();
        if want_urls != got_urls {
            mismatch!("{}: media header urls differ from the model", rel);
        }
    }
    rep.ok = rep.mismatch_total == 0;
    Ok(rep)
}

// ---------------------------------------------------------------------------
// Anchor re-location (STANDOFF §2.4): resolve every entry's anchor
// against a held edition of the base. Same edition: EXACT. Drifted
// edition: object keys re-base through the held object table; coordinate
// anchors transport only through a mapping scroll (base Collection 6,
// Chapter 8: `<old addr> -> <new addr>` lines — the profile's mapping
// convention). Nothing is ever heuristically re-attached.

#[derive(Debug)]
pub struct Detached {
    pub key: String,
    pub class: String, // span-edited | span-absent | key-retired
    pub quoted: String,
}

#[derive(Debug, Default)]
pub struct RelocReport {
    pub total: usize,
    pub exact: usize,
    pub relocated_verified: usize,
    pub relocated_moved: usize,
    pub lost: Vec<Detached>,
    pub ambiguous: Vec<Detached>,
}

fn scalar_slice(text: &str, start: usize, end: usize) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    if end > chars.len() || start > end {
        return None;
    }
    Some(chars[start..end].iter().collect())
}

fn find_occurrences(text: &str, needle: &str) -> Vec<usize> {
    if needle.is_empty() {
        return Vec::new();
    }
    let hay: Vec<char> = text.chars().collect();
    let nee: Vec<char> = needle.chars().collect();
    let mut out = Vec::new();
    if nee.len() > hay.len() {
        return out;
    }
    for i in 0..=(hay.len() - nee.len()) {
        if hay[i..i + nee.len()] == nee[..] {
            out.push(i);
        }
    }
    out
}

pub fn relocate(base_path: &Path, standoff_path: &Path) -> Result<RelocReport, String> {
    let base = load_map(base_path)?;
    let standoff = load_map(standoff_path)?;
    let held_checksum = edition_checksum(&to_phext_map(&base), manifest_coord());
    let held_pin = held_checksum.get(..16).unwrap_or("").to_string();
    let index = shipped_index(&base);
    // mapping scroll (present only in editions produced by a re-base)
    let mut mapping: HashMap<String, String> = HashMap::new();
    if let Some(text) = base.get(&coll_coord(1, 6, 8, 1, 1)) {
        for line in text.lines() {
            if let Some((a, b)) = line.split_once(" -> ") {
                mapping.insert(a.trim().to_string(), b.trim().to_string());
            }
        }
    }
    let entries = load_entries(&standoff)?;
    let mut rep = RelocReport { total: entries.len(), ..Default::default() };
    let detach = |rep: &mut RelocReport, e: &ParsedEntry, class: &str| {
        if rep.lost.len() < 1000 {
            rep.lost.push(Detached {
                key: format!("annotation:e-{}", e.key_n),
                class: class.to_string(),
                quoted: e.text.chars().take(80).collect(),
            });
        }
    };
    for e in &entries {
        let same_edition = e.target.pin == held_pin;
        // Resolve the held scroll this entry points at.
        let (coord, span) = match &e.target.at {
            Some((c, s, en)) => {
                if same_edition {
                    (*c, Some((*s, *en)))
                } else {
                    match mapping.get(&c.addr()) {
                        Some(new) => match C9::parse(new) {
                            Some(nc) => (nc, Some((*s, *en))),
                            None => {
                                detach(&mut rep, e, "span-absent");
                                continue;
                            }
                        },
                        None => {
                            detach(&mut rep, e, "span-absent");
                            continue;
                        }
                    }
                }
            }
            None => {
                let key = (
                    e.target.kind.clone().unwrap_or_default(),
                    e.target.key_slug.clone().unwrap_or_default(),
                );
                match index.get(&key) {
                    Some(c) => (*c, None),
                    None => {
                        detach(&mut rep, e, "key-retired");
                        continue;
                    }
                }
            }
        };
        let scroll = match base.get(&coord) {
            Some(s) => s.clone(),
            None => {
                detach(&mut rep, e, "span-absent");
                continue;
            }
        };
        let total = scroll.chars().count();
        let (start, end) = span.unwrap_or((0, total));
        // Point anchors: verify the point still lands inside the scroll.
        if start == end && e.text.is_empty() {
            if start <= total {
                if same_edition {
                    rep.exact += 1;
                } else {
                    rep.relocated_verified += 1;
                }
            } else {
                detach(&mut rep, e, "span-absent");
            }
            continue;
        }
        match scalar_slice(&scroll, start, end) {
            Some(slice) if slice == e.text && phext::checksum(&slice) == e.hash => {
                if same_edition {
                    rep.exact += 1;
                } else {
                    rep.relocated_verified += 1;
                }
            }
            _ => {
                if same_edition {
                    // Same pin but the span does not verify: the edition
                    // in hand is not the edition the pin names.
                    detach(&mut rep, e, "span-edited");
                    continue;
                }
                // Search the found scroll for the quoted span (§2.4 step 4).
                let mut hits = find_occurrences(&scroll, &e.text);
                if hits.len() > 1 {
                    let chars: Vec<char> = scroll.chars().collect();
                    let tlen = e.text.chars().count();
                    hits.retain(|&h| {
                        let before_ok = match &e.before {
                            None => true,
                            Some(b) => {
                                let bc: Vec<char> = b.chars().collect();
                                h >= bc.len() && chars[h - bc.len()..h] == bc[..]
                            }
                        };
                        let after_ok = match &e.after {
                            None => true,
                            Some(a) => {
                                let ac: Vec<char> = a.chars().collect();
                                h + tlen + ac.len() <= chars.len()
                                    && chars[h + tlen..h + tlen + ac.len()] == ac[..]
                            }
                        };
                        before_ok && after_ok
                    });
                }
                match hits.len() {
                    1 => rep.relocated_moved += 1,
                    0 => detach(
                        &mut rep,
                        e,
                        if end <= total { "span-edited" } else { "span-absent" },
                    ),
                    _ => {
                        if rep.ambiguous.len() < 1000 {
                            rep.ambiguous.push(Detached {
                                key: format!("annotation:e-{}", e.key_n),
                                class: "ambiguous".to_string(),
                                quoted: e.text.chars().take(80).collect(),
                            });
                        }
                    }
                }
            }
        }
    }
    Ok(rep)
}

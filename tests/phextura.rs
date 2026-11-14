//! Stage 0.3 tests: layout, entry grammar, validator, reconstruction,
//! re-location (including drifted-edition probes), and the TEI.md
//! conformance diff. Corpus acceptance lives in phextura_acceptance.rs.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use teixml_to_mutable::phextura::*;
use teixml_to_mutable::segment::BLOCK_ELEMENTS;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("teixml-phextura-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(p: &Path, bytes: &[u8]) {
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, bytes).unwrap();
}

const FIXTURE_A: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<?xml-model href="http://www.tei-c.org/release/xml/tei/custom/schema/relaxng/tei_all.rng" type="application/xml"?>
<!-- prolog comment -->
<!DOCTYPE TEI PUBLIC "-//TEI//DTD TEI//EN" "http://example.org/tei.dtd" [ <!ENTITY x "a>b"> <!-- subset comment --> ]>
<TEI xmlns="http://www.tei-c.org/ns/1.0" xml:id="doc-a">
<teiHeader><fileDesc><titleStmt><title>Fixture A</title></titleStmt>
<publicationStmt><p>Pub</p></publicationStmt></fileDesc>
<msDesc><msIdentifier><settlement>London</settlement><repository>Wellcome</repository><idno>MS.123</idno></msIdentifier></msDesc>
</teiHeader>
<text><body>
<div xml:id="d1"><head>First Section</head>
<p>Hello <hi rend="bold">mixed</hi> world <!-- inline comment --> tail.</p>
<p>See <ref target="#d2">next</ref> and <ref target="#missing">missing</ref> and <ref target="https://example.org/x">ext</ref>.</p>
<figure><graphic url="https://iiif.example.org/img1.jpg"/><figDesc>An image</figDesc></figure>
</div>
<div xml:id="d2"><head>Second</head><p>Text with astral 𝔘nicode and <foreign xml:lang="grc">λόγος</foreign>.</p></div>
<listBibl><bibl><author>Smith, John</author><title>Some Work</title><date when="1998">1998</date></bibl></listBibl>
</body></text>
</TEI>
<!-- epilog comment -->
"##;

fn fixture(name: &str) -> (PathBuf, PathBuf, PhexturaSummary) {
    let dir = tmp(name);
    let src = dir.join("src");
    write(&src.join("a.xml"), FIXTURE_A.as_bytes());
    write(&src.join("broken.xml"), b"<TEI><unclosed>");
    let out = dir.join("out");
    let sum = export_phextura(&src, &out).unwrap();
    (dir, out, sum)
}

#[test]
fn escaping_round_trip_and_strictness() {
    for v in [
        "",
        "plain",
        " lead",
        "trail ",
        " both ",
        "a\\b",
        "tab\there",
        "new\nline",
        "carriage\rreturn",
        " ",
        "\\",
        "astral 𝔘 and \\n literal",
        "trailing backslash\\",
    ] {
        assert_eq!(unescape_value(&escape_value(v)).unwrap(), v, "round trip {:?}", v);
    }
    assert!(unescape_value("bad \\q escape").is_err());
    assert!(unescape_value("trailing \\").is_err());
}

#[test]
fn slugify_rules() {
    assert_eq!(slugify("MS.123"), "ms-123");
    assert_eq!(slugify("First Section"), "first-section");
    assert_eq!(slugify("1998"), "id-1998");
    assert_eq!(slugify(""), "x");
    assert_eq!(slugify("λόγος"), "x");
    assert_eq!(slugify("a/b/c.xml"), "a-b-c-xml");
}

#[test]
fn doctype_and_marks_in_model() {
    let doc = teixml_to_mutable::parse_xml_full(FIXTURE_A.as_bytes()).unwrap();
    let dt = doc.doctype.expect("doctype parsed");
    assert_eq!(dt.name, "TEI");
    assert_eq!(dt.public_id.as_deref(), Some("-//TEI//DTD TEI//EN"));
    assert_eq!(dt.system_id.as_deref(), Some("http://example.org/tei.dtd"));
    let subset = dt.internal_subset.expect("subset captured");
    assert!(subset.contains("a>b"), "quoted > survives: {:?}", subset);
    assert!(subset.contains("subset comment"), "comment inside subset: {:?}", subset);
    assert_eq!(doc.prolog.len(), 2); // xml-model PI + prolog comment
    assert!(matches!(&doc.prolog[0], teixml_to_mutable::Node::Pi { target, .. } if target == "xml-model"));
    assert!(matches!(&doc.prolog[1], teixml_to_mutable::Node::Comment(t) if t.contains("prolog")));
    assert_eq!(doc.epilog.len(), 1);
}

#[test]
fn bom_prefixed_document_parses() {
    // Corpus files exist with a UTF-8 BOM before the XML declaration;
    // the prolog scanners must walk bytes without slicing mid-char.
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(FIXTURE_A.as_bytes());
    let doc = teixml_to_mutable::parse_xml_full(&bytes).unwrap();
    assert!(doc.doctype.is_some());
    assert_eq!(doc.prolog.len(), 2);
}

#[test]
fn fixture_pair_validates_and_reconstructs() {
    let (_dir, _out, sum) = fixture("full");
    assert_eq!(sum.documents, 1);
    assert_eq!(sum.entries.len(), 2);
    assert_eq!(sum.entries.iter().filter(|e| e.error.is_some()).count(), 1);
    assert!(sum.base_bytes > 0 && sum.standoff_bytes > 0);
    let kinds: HashMap<String, usize> = sum.entries_by_kind.iter().cloned().collect();
    assert_eq!(kinds["tei-element"], 34);
    assert_eq!(kinds["tei-comment"], 3);
    assert_eq!(kinds["tei-pi"], 1);
    assert_eq!(sum.refs.resolved, 1);
    assert_eq!(sum.refs.unresolved, 1);
    assert_eq!(sum.refs.external, 1);
    assert_eq!(sum.externals, 1);

    let v = validate_pair(&sum.base_path, &sum.standoff_path).unwrap();
    assert!(v.ok, "validator failures: {:?}", v.failures);
    assert!(v.base_checksum_ok && v.standoff_checksum_ok);
    assert_eq!(v.entries, sum.total_entries);

    let src = _dir.join("src");
    let r = check_reconstruction(&sum.base_path, &sum.standoff_path, &src).unwrap();
    assert!(r.ok, "recon mismatches: {:?}", r.mismatches);
    assert_eq!(r.files, 2);
    assert_eq!(r.originals_verified, 2);
    assert_eq!(r.elements, 34);
    assert_eq!(r.comments, 3);
    assert_eq!(r.pis, 1);
    assert_eq!(r.doctypes, 1);

    let rel = relocate(&sum.base_path, &sum.standoff_path).unwrap();
    assert_eq!(rel.exact, rel.total);
    assert!(rel.lost.is_empty() && rel.ambiguous.is_empty());
}

#[test]
fn fixture_layout_spot_checks() {
    let (_dir, _out, sum) = fixture("layout");
    let base = load_map(&sum.base_path).unwrap();
    // corpus manifest at Series 1, Collection 6
    let manifest = &base[&manifest_coord()];
    assert!(manifest.contains("corpus: src"));
    assert!(manifest.contains("tei-profile: 0.1"));
    assert!(manifest.contains("external: https://iiif.example.org/img1.jpg"));
    // document a.xml is Series 2 (sorted order: a.xml, broken.xml)
    let meta = &base[&C9::new((1, 1, 2), (6, 1, 1), (1, 1, 1))];
    assert!(meta.contains("key: paper:ms-123"), "paper keyed by idno: {}", meta);
    assert!(meta.contains("title: Fixture A"));
    assert!(meta.contains("ms-idno: MS.123"));
    assert!(meta.contains("doctype-name: TEI"));
    // heading scroll carries the section key line
    let mut heading: Option<&String> = None;
    for (c, t) in &base {
        if c.z.2 == 2 && t.starts_with("@heading") && t.contains("First Section") {
            heading = Some(t);
            assert_eq!(c.y, (1, 1, 2), "headings live in the text book");
        }
    }
    let heading = heading.expect("heading scroll present");
    assert!(heading.contains("key: section:first-section"), "{}", heading);
    // bibentry in Collection 2 with the normative text: line
    let bib: Vec<&String> = base
        .iter()
        .filter(|(c, _)| c.z.2 == 2 && c.y == (2, 1, 1))
        .map(|(_, t)| t)
        .collect();
    assert_eq!(bib.len(), 1);
    assert!(bib[0].contains("key: bibentry:smith-1998"), "{}", bib[0]);
    assert!(bib[0].contains("text: Smith, JohnSome Work1998"), "{}", bib[0]);
    // media header in Collection 3
    let media: Vec<&String> = base
        .iter()
        .filter(|(c, _)| c.z.2 == 2 && c.y == (3, 1, 1))
        .map(|(_, t)| t)
        .collect();
    assert_eq!(media.len(), 1);
    assert!(media[0].contains("key: figure:img1"));
    assert!(media[0].contains("checksum: absent — external, not hoisted"));
    // original hoisted verbatim in Collection 5
    let content = &base[&C9::new((1, 1, 2), (5, 1, 1), (1, 1, 2))];
    assert_eq!(content, FIXTURE_A);
    // doctype subset hoisted at Collection 5, chapter 2
    let subset = &base[&C9::new((1, 1, 2), (5, 1, 1), (2, 1, 2))];
    assert!(subset.contains("a>b") && subset.contains("subset comment"));
    // the failed file: original + failure metadata only, no body
    assert!(base.keys().any(|c| c.z.2 == 3 && c.y == (5, 1, 1)));
    assert!(!base.keys().any(|c| c.z.2 == 3 && c.y.0 == 1));
    let fmeta = &base[&C9::new((1, 1, 3), (6, 1, 1), (1, 1, 1))];
    assert!(fmeta.contains("conversion: failed"));
}

#[test]
fn segmentation_matches_mutable_document() {
    // The shared segmentation must reproduce the 0.2 document exactly:
    // same blocks, same plain text, same annotation count.
    let root = teixml_to_mutable::parse_xml(FIXTURE_A.as_bytes()).unwrap();
    let doc = teixml_to_mutable::mutable::build_document("a.xml", &root);
    let flat = teixml_to_mutable::segment::flatten(&root);
    let seg = teixml_to_mutable::segment::segment_document(&root, &flat);
    let kept = teixml_to_mutable::segment::kept_map(&seg);
    let kept_segs: Vec<_> = seg
        .segments
        .iter()
        .zip(kept.iter())
        .filter(|(_, k)| k.is_some())
        .map(|(s, _)| s)
        .collect();
    assert_eq!(kept_segs.len(), doc.blocks);
    let concat: String = kept_segs.iter().map(|s| s.text.as_str()).collect();
    assert_eq!(concat, doc.plain_text);
    let inlines: usize = kept_segs.iter().map(|s| s.inlines.len()).sum();
    assert_eq!(inlines, doc.annotations);
}

/// Rewrite a base map as a new edition: apply `edit` to the map, then
/// fix the manifest checksum line. Returns the new file path.
fn reedition(
    dir: &Path,
    base: &HashMap<C9, String>,
    edit: impl FnOnce(&mut HashMap<C9, String>),
) -> PathBuf {
    let mut map = base.clone();
    edit(&mut map);
    let mut phex: HashMap<libphext::phext::Coordinate, String> =
        map.iter().map(|(c, s)| (c.phext(), s.clone())).collect();
    let checksum = edition_checksum(&phex, manifest_coord());
    let m = phex.get_mut(&manifest_coord().phext()).unwrap();
    let stripped = strip_checksum_line(m);
    *m = format!("{}\nchecksum: xxh3-128:{}", stripped, checksum);
    let path = dir.join("reedition.phext");
    std::fs::write(&path, canonical_bytes(&phex)).unwrap();
    path
}

#[test]
fn drift_probe_edited_span_detaches_never_reattaches() {
    let (dir, _out, sum) = fixture("drift");
    let base = load_map(&sum.base_path).unwrap();
    // Edit the First Section heading scroll's text in place.
    let heading_coord = base
        .iter()
        .find(|(_, t)| t.starts_with("@heading") && t.contains("First Section"))
        .map(|(c, _)| *c)
        .unwrap();
    let edited = reedition(&dir, &base, |map| {
        let t = map.get_mut(&heading_coord).unwrap();
        *t = t.replace("First Section", "Renamed Heading");
    });
    let rel = relocate(&edited, &sum.standoff_path).unwrap();
    assert_eq!(rel.exact, 0, "nothing may verify as EXACT under a foreign pin");
    assert_eq!(rel.relocated_moved, 0, "no mapping scroll: nothing transports");
    assert!(!rel.lost.is_empty(), "drift must detach loudly");
    assert!(
        rel.lost.iter().any(|d| d.class == "span-edited"),
        "the edited section's anchor reports span-edited: {:?}",
        rel.lost.iter().map(|d| (d.key.clone(), d.class.clone())).collect::<Vec<_>>()
    );
}

#[test]
fn rebase_probe_mapping_transports_coordinate_anchors() {
    let (dir, _out, sum) = fixture("rebase");
    let base = load_map(&sum.base_path).unwrap();
    // Re-base: series 2 (a.xml) moves to series 9; a mapping scroll
    // records every moved coordinate; the object table is rewritten to
    // the new coordinates, as a re-basing tool would emit.
    let rebased = reedition(&dir, &base, |map| {
        let moved: Vec<C9> = map.keys().filter(|c| c.z.2 == 2).copied().collect();
        let mut mapping_lines: Vec<String> = Vec::new();
        for c in &moved {
            let nc = C9::new((1, 1, 9), c.y, c.x);
            mapping_lines.push(format!("{} -> {}", c.addr(), nc.addr()));
            let text = map.remove(c).unwrap();
            map.insert(nc, text);
        }
        // rewrite coordinate values inside Series-1 scrolls (index,
        // ledger, manifest) and inside the moved metadata scroll
        let rewrite = |text: &str| -> String {
            let mut t = text.to_string();
            for c in &moved {
                let nc = C9::new((1, 1, 9), c.y, c.x);
                t = t.replace(&c.addr(), &nc.addr());
            }
            t
        };
        let series1: Vec<C9> = map.keys().filter(|c| c.z.2 == 1).copied().collect();
        for c in series1 {
            let old = map.get(&c).unwrap().clone();
            map.insert(c, rewrite(&old));
        }
        let meta9 = C9::new((1, 1, 9), (6, 1, 1), (1, 1, 1));
        let old = map.get(&meta9).unwrap().clone();
        map.insert(meta9, rewrite(&old));
        map.insert(C9::new((1, 1, 1), (6, 1, 1), (8, 1, 1)), mapping_lines.join("\n"));
    });
    let rel = relocate(&rebased, &sum.standoff_path).unwrap();
    assert_eq!(rel.exact, 0);
    assert_eq!(rel.relocated_moved, 0, "spans did not move within their scrolls");
    // every entry of the moved document (and every object anchor)
    // re-locates through the mapping scroll / object table: a.xml is
    // the only converted document, so all of its entries must verify.
    assert_eq!(
        rel.relocated_verified, sum.total_entries,
        "lost: {:?}",
        rel.lost.iter().map(|d| (d.key.clone(), d.class.clone())).collect::<Vec<_>>()
    );
    assert!(rel.lost.is_empty() && rel.ambiguous.is_empty());
}

#[test]
fn ambiguous_probe_repeated_span_with_identical_context() {
    // Hand-built pair: one scroll whose text repeats the quoted span
    // with identical context; the entry's recorded span no longer holds
    // the text, and search cannot choose — AMBIGUOUS, never a guess.
    let dir = tmp("ambig");
    let scroll_coord = C9::new((1, 1, 2), (1, 1, 1), (1, 1, 1));
    let scroll_text = "@prose\ntei-element: p\n\nXabY XabY";
    let mut base: HashMap<libphext::phext::Coordinate, String> = HashMap::new();
    base.insert(scroll_coord.phext(), scroll_text.to_string());
    base.insert(
        manifest_coord().phext(),
        "corpus: hand\nkind: tei-corpus\ntei-profile: 0.1".to_string(),
    );
    let checksum = edition_checksum(&base, manifest_coord());
    let m = base.get_mut(&manifest_coord().phext()).unwrap();
    *m = format!("{}\nchecksum: xxh3-128:{}", m, checksum);
    let base_path = dir.join("hand.phext");
    std::fs::write(&base_path, canonical_bytes(&base)).unwrap();

    // the entry was written against an older pin; its span (0..2 of the
    // body region) does not hold "ab" at the recorded offsets.
    let entry = "@annotation\nkind: tei-element\nkey: annotation:e-1\n\
        target: px2:corpus:hand@e:0000000000000000#at:1.1.2/1.1.1/1.1.1@26..28\n\
        target-hash: xxh3-128:00000000000000000000000000000000\n\
        target-text: ab\ntarget-before: X\ntarget-after: Y\n\
        tei-element: hi\nauthor: teixml-to-mutable\n\
        produced-by: teixml-to-mutable 0.3.0\ncreated: 2026-11-14T00:00:00Z\n\nab";
    let mut standoff: HashMap<libphext::phext::Coordinate, String> = HashMap::new();
    let entry_coord = C9::new((1, 1, 1), (1, 1, 1), (2, 1, 1));
    standoff.insert(entry_coord.phext(), entry.to_string());
    standoff.insert(
        standoff_meta_coord().phext(),
        "standoff-of: px2:corpus:hand\nstandoff-profile: 0.1\nentries: 1".to_string(),
    );
    // mapping scroll transports the (unchanged) coordinate
    let mut base2: HashMap<C9, String> = load_map(&base_path).unwrap();
    base2.insert(
        C9::new((1, 1, 1), (6, 1, 1), (8, 1, 1)),
        format!("{} -> {}", scroll_coord.addr(), scroll_coord.addr()),
    );
    let base2_path = reedition(&dir, &base2, |_| {});
    let standoff_path = dir.join("hand.standoff.phext");
    std::fs::write(&standoff_path, canonical_bytes(&standoff)).unwrap();
    let rel = relocate(&base2_path, &standoff_path).unwrap();
    assert_eq!(rel.ambiguous.len(), 1, "report: {:?}", rel);
    assert!(rel.lost.is_empty());
    assert_eq!(rel.relocated_moved, 0);
}

#[test]
fn tei_md_table_conformance() {
    // The profile document at the crate root is the normative registry;
    // the compiled-in tables must not drift from it.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("TEI.md");
    let text = std::fs::read_to_string(&path)
        .expect("TEI.md must ship at the crate root (identical bytes to phextura repo TEI.md)");
    let line = |prefix: &str| -> Vec<String> {
        let l = text
            .lines()
            .find(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("TEI.md missing normative line {}", prefix));
        l[prefix.len()..]
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    let mut doc_blocks = line("block-elements:");
    doc_blocks.sort();
    let mut code_blocks: Vec<String> = BLOCK_ELEMENTS.iter().map(|s| s.to_string()).collect();
    code_blocks.sort();
    assert_eq!(doc_blocks, code_blocks, "segmentation table drift");
    assert_eq!(
        line("pointing-attributes:"),
        POINTING_ATTRS.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        "pointing attribute list drift"
    );
    assert_eq!(
        line("key-kinds:"),
        KIND_ORDER.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        "key kind list drift"
    );
    assert_eq!(
        line("section-elements:"),
        SECTION_ELEMENTS.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        "section element list drift"
    );
}

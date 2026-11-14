use libphext::phext;
use std::path::{Path, PathBuf};
use teixml_to_mutable::{append_member, convert_dir, verify, ChainReader, ChainWriter};

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("teixml-basic-{}-{}", std::process::id(), name));
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

const TEI_A: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<TEI xmlns=\"http://www.tei-c.org/ns/1.0\"><teiHeader><fileDesc><titleStmt><title xml:id=\"t1\" type=\"main\">A Title</title></titleStmt></fileDesc></teiHeader><text><body><div><p>Hello <hi rend=\"bold\">mixed</hi> tail text.</p><p>Second para</p></div></body></text></TEI>";
const TEI_B: &str = "<TEI xmlns=\"http://www.tei-c.org/ns/1.0\"><teiHeader><fileDesc><titleStmt><title>B</title></titleStmt></fileDesc></teiHeader><text><body><p>Only para</p></body></text></TEI>";

#[test]
fn convert_extract_verify_small() {
    let dir = tmp("small");
    let src = dir.join("src");
    write(&src.join("a.xml"), TEI_A.as_bytes());
    write(&src.join("sub/b.xml"), TEI_B.as_bytes());
    let out = dir.join("out.phext");
    let sum = convert_dir(&src, &out).unwrap();
    assert_eq!(sum.entries.len(), 2);
    assert!(sum.entries.iter().all(|e| e.error.is_none()));
    let rep = verify(&out, Some(&src)).unwrap();
    assert_eq!(rep.originals_verified, 2);
    assert_eq!(rep.failures, 0);
    assert!(rep.dangling_refs.is_empty());
    assert!(rep.unreachable_universes.is_empty());
    assert!(rep.text_mismatches.is_empty(), "{:?}", rep.text_mismatches);
    // extract round trip
    let reader = ChainReader::open(&out).unwrap();
    let bytes = teixml_to_mutable::extract_original(&reader, "a.xml").unwrap();
    assert_eq!(bytes, TEI_A.as_bytes());
    let bytes = teixml_to_mutable::extract_original(&reader, "sub/b.xml").unwrap();
    assert_eq!(bytes, TEI_B.as_bytes());
}

#[test]
fn malformed_and_binary_are_named_failures_but_kept() {
    let dir = tmp("bad");
    let src = dir.join("src");
    write(&src.join("good.xml"), TEI_B.as_bytes());
    write(&src.join("broken.xml"), b"<TEI><unclosed>");
    let binary_bytes: Vec<u8> = vec![0xFF, 0xFE, 0x3C, 0x00, 0x54, 0x00, 0xE9, 0x00];
    write(&src.join("utf16.xml"), &binary_bytes);
    let out = dir.join("out.phext");
    let sum = convert_dir(&src, &out).unwrap();
    assert_eq!(sum.entries.len(), 3);
    let failed: Vec<&str> = sum
        .entries
        .iter()
        .filter(|e| e.error.is_some())
        .map(|e| e.rel.as_str())
        .collect();
    assert_eq!(failed.len(), 2, "{:?}", failed);
    assert!(failed.contains(&"broken.xml") && failed.contains(&"utf16.xml"));
    let reader = ChainReader::open(&out).unwrap();
    assert_eq!(
        teixml_to_mutable::extract_original(&reader, "utf16.xml").unwrap(),
        binary_bytes
    );
    assert_eq!(
        teixml_to_mutable::extract_original(&reader, "broken.xml").unwrap(),
        b"<TEI><unclosed>"
    );
    let rep = verify(&out, None).unwrap();
    assert_eq!(rep.originals_verified, 3);
    assert_eq!(rep.failures, 2);
}

#[test]
fn mutation_changes_only_named_scrolls() {
    let dir = tmp("mut");
    let src = dir.join("src");
    write(&src.join("a.xml"), TEI_A.as_bytes());
    let out1 = dir.join("one.phext");
    convert_dir(&src, &out1).unwrap();
    let edited = TEI_A.replace("Hello", "Goodbye");
    write(&src.join("a.xml"), edited.as_bytes());
    let out2 = dir.join("two.phext");
    convert_dir(&src, &out2).unwrap();
    let s1 = std::fs::read_to_string(&out1).unwrap();
    let s2 = std::fs::read_to_string(&out2).unwrap();
    let c1 = phext::parse_chains(&s1);
    let c2 = phext::parse_chains(&s2);
    assert_eq!(c1[0].members.len(), c2[0].members.len());
    let mut changed_members: Vec<usize> = Vec::new();
    for (i, (m1, m2)) in c1[0].members.iter().zip(c2[0].members.iter()).enumerate() {
        if m1 != m2 {
            changed_members.push(i + 1);
        }
    }
    // $1 (original + index) and exactly ONE converted universe (the div's)
    assert_eq!(changed_members.len(), 2, "changed: {:?}", changed_members);
    assert_eq!(changed_members[0], 1);
    let u = changed_members[1];
    let r1 = ChainReader::open(&out1).unwrap();
    let r2 = ChainReader::open(&out2).unwrap();
    let s1s = r1.scrolls_of(u);
    let s2s = r2.scrolls_of(u);
    assert_eq!(s1s.len(), s2s.len());
    let diff: Vec<usize> = s1s
        .iter()
        .zip(s2s.iter())
        .filter(|(a, b)| a.1 != b.1)
        .map(|(a, _)| a.0)
        .collect();
    assert_eq!(diff.len(), 1, "scroll diffs: {:?}", diff);
}

#[test]
fn wal_append_leaves_prior_bytes_untouched() {
    let dir = tmp("wal");
    let path = dir.join("c.phext");
    let mut w = ChainWriter::create(&path).unwrap();
    w.write_member("first member").unwrap();
    w.write_member("second\u{17}member").unwrap();
    w.close().unwrap();
    let before = std::fs::read(&path).unwrap();
    append_member(&path, "third member").unwrap();
    let after = std::fs::read(&path).unwrap();
    // everything except the final close byte of `before` is a prefix of `after`
    assert_eq!(&after[..before.len() - 1], &before[..before.len() - 1]);
    let text = String::from_utf8(after).unwrap();
    let chains = phext::parse_chains(&text);
    assert_eq!(chains[0].members.len(), 3);
    assert!(chains[0].closed);
}

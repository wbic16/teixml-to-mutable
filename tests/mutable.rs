//! Stage 0.2 integration tests: a small TEI corpus exported as a Mutable
//! native Cavern zip, checked structurally (zip contents, database
//! identity) without needing Mutable itself. Mutable-side acceptance
//! (its own code opening the Cavern) is a ranch procedure; the full
//! Wellcome corpus run lives in mutable_acceptance.rs.
use std::io::Read;
use std::path::PathBuf;
use teixml_to_mutable::mutable::export_mutable;
use teixml_to_mutable::sha256_hex;

fn fixture() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("teixml-mut-fixture-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("Arabic")).unwrap();
    std::fs::write(
        dir.join("Arabic/MS_1.xml"),
        r#"<?xml version="1.0" encoding="utf-8"?>
<TEI xmlns="http://www.tei-c.org/ns/1.0">
<teiHeader><fileDesc><titleStmt><title>Manuscript One</title></titleStmt>
<sourceDesc><msDesc><msIdentifier><idno>MS 1</idno></msIdentifier>
<msContents><msItem><p>A <persName>person</persName> wrote this.</p></msItem></msContents>
</msDesc></sourceDesc></fileDesc></teiHeader>
<text><body><div><head>Opening</head><p>Body text.<lb/>More.</p></div></body></text>
</TEI>"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("plain.xml"),
        r#"<TEI><text><body><p>No header here.</p></body></text></TEI>"#,
    )
    .unwrap();
    std::fs::write(dir.join("broken.xml"), "<TEI><text><body><p>unclosed").unwrap();
    dir
}

#[test]
fn export_produces_native_cavern_zip() {
    let dir = fixture();
    let out = dir.join("out.zip");
    let sum = export_mutable(&dir, &out).unwrap();
    assert_eq!(sum.entries.len(), 3);
    assert_eq!(sum.documents, 2);
    let failures: Vec<&str> = sum.entries.iter().filter(|e| e.error.is_some()).map(|e| e.rel.as_str()).collect();
    assert_eq!(failures, ["broken.xml"], "failures are named, never silent");
    let doc1 = sum.entries.iter().find(|e| e.rel == "Arabic/MS_1.xml").unwrap();
    assert_eq!(doc1.title.as_deref(), Some("Manuscript One"));
    assert_eq!(doc1.doc_rel.as_deref(), Some("Arabic/MS_1.mutable.json"));
    assert!(doc1.annotations >= 1);

    let file = std::fs::File::open(&out).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    let mut names: Vec<String> = zip.file_names().map(|s| s.to_string()).collect();
    names.sort();
    for expected in [
        ".mutable/mutable.db",
        ".mutable/audit.db",
        ".mutable/cavern-state.json",
        ".mutable/writer.lock",
        "Arabic/MS_1.xml",
        "Arabic/MS_1.mutable.json",
        "plain.xml",
        "plain.mutable.json",
        "broken.xml",
    ] {
        assert!(names.iter().any(|n| n == expected), "missing {} in {:?}", expected, names);
    }
    // pair home for doc 1, named by Mutable's rule: sha256(resourceId)
    let rid = doc1.resource_id.clone().unwrap();
    let home = format!("Arabic/.mutable-pair-{}", sha256_hex(rid.as_bytes()));
    for suffix in ["receipt.json", "tei-import-1/native", "tei-import-1/intent.json", "writer.lock"] {
        let want = format!("{}/{}", home, suffix);
        assert!(names.iter().any(|n| n == &want), "missing {} in {:?}", want, names);
    }
    // the failed file has NO document and NO pair home
    assert!(!names.iter().any(|n| n.contains("broken.mutable")));

    // originals ride verbatim
    let mut original = String::new();
    zip.by_name("Arabic/MS_1.xml").unwrap().read_to_string(&mut original).unwrap();
    assert_eq!(original, std::fs::read_to_string(dir.join("Arabic/MS_1.xml")).unwrap());

    // generation copy is byte-identical to the document; receipt hashes it
    let mut doc_bytes = Vec::new();
    zip.by_name("Arabic/MS_1.mutable.json").unwrap().read_to_end(&mut doc_bytes).unwrap();
    let mut gen_bytes = Vec::new();
    zip.by_name(&format!("{}/tei-import-1/native", home)).unwrap().read_to_end(&mut gen_bytes).unwrap();
    assert_eq!(doc_bytes, gen_bytes);
    let mut receipt = String::new();
    zip.by_name(&format!("{}/receipt.json", home)).unwrap().read_to_string(&mut receipt).unwrap();
    assert!(receipt.contains(&format!("\"nativeHash\":\"{}\"", sha256_hex(&doc_bytes))), "{}", receipt);
    assert!(receipt.contains("\"version\":2"));

    // cavern-state guid == both databases' vaultGuid
    let mut state = String::new();
    zip.by_name(".mutable/cavern-state.json").unwrap().read_to_string(&mut state).unwrap();
    assert!(state.contains(&format!("\"cavernGuid\":\"{}\"", sum.vault_guid)), "{}", state);
    assert!(state.contains("\"mode\":\"native\""));
    let tmp = dir.join("dbcheck");
    std::fs::create_dir_all(&tmp).unwrap();
    for kind in ["mutable", "audit"] {
        let mut bytes = Vec::new();
        zip.by_name(&format!(".mutable/{}.db", kind)).unwrap().read_to_end(&mut bytes).unwrap();
        let p = tmp.join(format!("{}.db", kind));
        std::fs::write(&p, &bytes).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        let g: String = conn.query_row("SELECT value FROM SchemaInfo WHERE key='vaultGuid'", [], |r| r.get(0)).unwrap();
        assert_eq!(g, sum.vault_guid, "{} vaultGuid", kind);
        let integrity: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
        assert_eq!(integrity, "ok");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

//! Conformance: our reader index vs libphext reading the SAME bytes.
//! Corpus = files/strings our code did not write (libphext's own fixture
//! and the literal streams from libphext's test_chain.rs).
use libphext::phext;
use std::io::Write;
use teixml_to_mutable::{ChainReader, ChainWriter};

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("teixml-conf-{}-{}", std::process::id(), name));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Wrap a foreign single phext as a one-member closed chain and compare
/// every scroll: reader index slice vs libphext::fetch on the same member.
fn check_member(member: &str, tag: &str) {
    let dir = tmp(tag);
    let path = dir.join("c.phext");
    let mut w = ChainWriter::create(&path).unwrap();
    w.write_member(member).unwrap();
    w.close().unwrap();
    let reader = ChainReader::open(&path).unwrap();
    let map = phext::explode(member);
    assert!(!map.is_empty(), "foreign member must have scrolls");
    for (coord, want) in &map {
        let got = reader.get(1, coord).unwrap_or_else(|| panic!("missing {:?}", coord));
        assert_eq!(got, want, "scroll {:?} diverges", coord);
        assert_eq!(phext::fetch(member, coord.clone()), *want);
    }
}

#[test]
fn foreign_fixture_helios() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/regression-1-helios.phext");
    let member = std::fs::read_to_string(&fixture).expect("helios fixture present");
    assert!(
        !member.contains(phext::CHAIN_BREAK) && !member.contains(phext::CHAIN_CLOSE),
        "fixture unexpectedly contains chain bytes"
    );
    check_member(&member, "helios");
}

#[test]
fn foreign_streams_from_libphext_tests() {
    // literals taken from libphext 0.6.0 src/test_chain.rs (not our code)
    for (i, member) in [
        "alpha\u{17}beta\u{1}gamma",
        "edition one",
        "a\u{17}b\u{18}c\u{19}d",
        "x",
        "first scroll\u{17}second scroll\u{17}third scroll",
    ]
    .iter()
    .enumerate()
    {
        check_member(member, &format!("stream{}", i));
    }
}

#[test]
fn writer_matches_libphext_serialize() {
    let members = vec![
        "one".to_string(),
        "two\u{17}scrolls".to_string(),
        String::new(),
        "four\u{1}library".to_string(),
    ];
    let dir = tmp("writer");
    let path = dir.join("w.phext");
    let mut w = ChainWriter::create(&path).unwrap();
    for m in &members {
        w.write_member(m).unwrap();
    }
    w.close().unwrap();
    let ours = std::fs::read(&path).unwrap();
    let chain = phext::Chain { members: members.clone(), closed: true };
    assert_eq!(ours, chain.serialize().as_bytes());
    // and a file written by libphext's serializer opens in our reader
    let path2 = dir.join("w2.phext");
    let mut f = std::fs::File::create(&path2).unwrap();
    f.write_all(chain.serialize().as_bytes()).unwrap();
    drop(f);
    let reader = ChainReader::open(&path2).unwrap();
    assert_eq!(reader.member_count(), members.len());
    for (i, m) in members.iter().enumerate() {
        assert_eq!(reader.member(i + 1).unwrap(), m);
    }
}

//! SPEC 0.1 v3 acceptance tests 1–6 against the full Wellcome corpus.
//! Ignored by default; run with TEIXML_CORPUS=<dir> cargo test --release -- --ignored
use std::path::PathBuf;
use std::time::Instant;
use teixml_to_mutable::{convert_dir, verify};

#[test]
#[ignore]
fn wellcome_acceptance() {
    let corpus = std::env::var("TEIXML_CORPUS").expect("TEIXML_CORPUS must name the corpus dir");
    let dir = PathBuf::from(&corpus);
    let out = std::env::temp_dir().join(format!("teixml-acc-{}.phext", std::process::id()));
    let t0 = Instant::now();
    let sum = convert_dir(&dir, &out).unwrap();
    let elapsed = t0.elapsed();
    let total_in: u64 = sum.entries.iter().map(|e| e.size as u64).sum();
    let failed = sum.entries.iter().filter(|e| e.error.is_some()).count();
    eprintln!(
        "ACCEPTANCE convert: files={} converted={} failures={} members={} in_bytes={} out_bytes={} elapsed_s={:.2} files_per_s={:.1} mb_per_s={:.2}",
        sum.entries.len(),
        sum.entries.len() - failed,
        failed,
        sum.members_written,
        total_in,
        sum.out_bytes,
        elapsed.as_secs_f64(),
        sum.entries.len() as f64 / elapsed.as_secs_f64(),
        (total_in as f64 / 1_000_000.0) / elapsed.as_secs_f64()
    );
    // test 1: every file converted or named in the failure report (entries carry errors)
    assert_eq!(sum.entries.len(), failed + sum.entries.iter().filter(|e| e.error.is_none()).count());
    let rep = verify(&out, Some(&dir)).unwrap();
    eprintln!("ACCEPTANCE verify: {:?}", rep);
    // test 2 (closed chain + libphext parse) is inside ChainReader::open
    // test 4: originals byte-identical for EVERY file
    assert_eq!(rep.originals_verified, rep.files);
    // test 6: reference graph fully resolved and reachable
    assert!(rep.dangling_refs.is_empty(), "{:?}", rep.dangling_refs);
    assert!(rep.unreachable_universes.is_empty(), "{:?}", rep.unreachable_universes);
    // test 3: text-node sequences equal for every converted file
    assert!(rep.text_mismatches.is_empty(), "{:?}", rep.text_mismatches);
}

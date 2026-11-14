//! Stage 0.3 acceptance against the full Wellcome corpus (SPEC-0.3 §5,
//! T1–T5, T8). Ignored by default; run with
//! TEIXML_CORPUS=<dir> cargo test --release --test phextura_acceptance -- --ignored
use std::path::PathBuf;
use std::time::Instant;
use teixml_to_mutable::mutable::export_mutable;
use teixml_to_mutable::phextura::{
    check_reconstruction, export_phextura, relocate, validate_pair,
};

#[test]
#[ignore]
fn wellcome_phextura_acceptance() {
    let corpus = std::env::var("TEIXML_CORPUS").expect("TEIXML_CORPUS must name the corpus dir");
    let dir = PathBuf::from(&corpus);
    let out = std::env::temp_dir().join(format!("teixml-phextura-acc-{}", std::process::id()));
    let t0 = Instant::now();
    let sum = export_phextura(&dir, &out).unwrap();
    let elapsed = t0.elapsed();
    let failed: Vec<&str> = sum
        .entries
        .iter()
        .filter(|e| e.error.is_some())
        .map(|e| e.rel.as_str())
        .collect();
    eprintln!(
        "PHEXTURA ACCEPTANCE export: files={} converted={} failures={} entries={} base_bytes={} standoff_bytes={} base_scrolls={} standoff_scrolls={} externals={} pin={} elapsed_s={:.2}",
        sum.entries.len(),
        sum.documents,
        failed.len(),
        sum.total_entries,
        sum.base_bytes,
        sum.standoff_bytes,
        sum.base_scrolls,
        sum.standoff_scrolls,
        sum.externals,
        sum.pin,
        elapsed.as_secs_f64()
    );
    eprintln!("kinds: {:?}", sum.entries_by_kind);
    eprintln!(
        "refs: resolved={} unresolved={} external={}",
        sum.refs.resolved, sum.refs.unresolved, sum.refs.external
    );
    // T1: parity with stages 0.1/0.2 — 1,875 converted, the same 11 named
    // failures, zero silent skips. The failure SET is proven against the
    // 0.2 exporter's own accounting on the same corpus.
    assert_eq!(sum.entries.len(), sum.documents + failed.len(), "every file accounted for");
    assert_eq!(sum.documents, 1875, "converted count must match 0.1/0.2");
    assert_eq!(failed.len(), 11, "failure count must match 0.1/0.2");
    let zip_out = std::env::temp_dir().join(format!("teixml-acc-parity-{}.zip", std::process::id()));
    let msum = export_mutable(&dir, &zip_out).unwrap();
    let mut mfailed: Vec<&str> = msum
        .entries
        .iter()
        .filter(|e| e.error.is_some())
        .map(|e| e.rel.as_str())
        .collect();
    let mut mine = failed.clone();
    mfailed.sort();
    mine.sort();
    assert_eq!(mine, mfailed, "failure set must equal the 0.2 failure set");
    let _ = std::fs::remove_file(&zip_out);

    // T2: DESIGN §7 validation
    let v = validate_pair(&sum.base_path, &sum.standoff_path).unwrap();
    eprintln!(
        "VALIDATOR: ok={} keys={} entries={} media={} externals={} bare={} resolvable_bare={} failures={:?}",
        v.ok, v.keys_indexed, v.entries, v.media_headers, v.externals_declared,
        v.bare_coords_in_prose, v.resolvable_bare_coords, v.failures
    );
    assert!(v.ok, "validator failures: {:?}", v.failures);
    assert!(v.base_checksum_ok && v.standoff_checksum_ok);

    // T3 + T4: reconstruction (TEI-equivalence) and originals
    let t1 = Instant::now();
    let r = check_reconstruction(&sum.base_path, &sum.standoff_path, &dir).unwrap();
    eprintln!(
        "RECON: ok={} files={} originals={} segments={} elements={} attributes={} comments={} pis={} doctypes={} refs={}/{}/{} mismatches={} elapsed_s={:.2}",
        r.ok, r.files, r.originals_verified, r.segments, r.elements, r.attributes,
        r.comments, r.pis, r.doctypes, r.refs_resolved, r.refs_unresolved, r.refs_external,
        r.mismatch_total,
        t1.elapsed().as_secs_f64()
    );
    for m in &r.mismatches {
        eprintln!("  mismatch: {}", m);
    }
    assert!(r.ok, "reconstruction mismatches: {}", r.mismatch_total);
    assert_eq!(r.originals_verified, r.files, "T4: every original byte-identical");
    assert_eq!(r.files, sum.entries.len());
    assert_eq!(r.refs_resolved, sum.refs.resolved);
    assert_eq!(r.refs_unresolved, sum.refs.unresolved);
    assert_eq!(r.refs_external, sum.refs.external);

    // T5: every anchor resolves EXACT against the emitted edition
    let rel = relocate(&sum.base_path, &sum.standoff_path).unwrap();
    eprintln!(
        "RELOCATE: total={} exact={} verified={} moved={} lost={} ambiguous={}",
        rel.total,
        rel.exact,
        rel.relocated_verified,
        rel.relocated_moved,
        rel.lost.len(),
        rel.ambiguous.len()
    );
    assert_eq!(rel.exact, rel.total, "all anchors EXACT on the pinned edition");
    assert!(rel.lost.is_empty() && rel.ambiguous.is_empty());
    let _ = std::fs::remove_dir_all(&out);
}

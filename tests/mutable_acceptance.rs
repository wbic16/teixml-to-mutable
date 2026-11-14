//! Stage 0.2 acceptance against the full Wellcome corpus.
//! Ignored by default; run with TEIXML_CORPUS=<dir> cargo test --release -- --ignored
//!
//! Checks: every file converted or named (0.1 parity: 1,875 / 11 expected
//! on the 2026-11-14 corpus), and per-document text fidelity — the
//! document's plain text and the source's text-node sequence carry the
//! same non-whitespace characters in the same order (the segmentation
//! normalisation of STAGE2-RECON.md §5: whitespace-only runs between
//! block-level elements are not represented; everything else is exact).
use std::path::PathBuf;
use std::time::Instant;
use teixml_to_mutable::mutable::{build_document, export_mutable};
use teixml_to_mutable::parse_xml;

fn non_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

#[test]
#[ignore]
fn wellcome_mutable_acceptance() {
    let corpus = std::env::var("TEIXML_CORPUS").expect("TEIXML_CORPUS must name the corpus dir");
    let dir = PathBuf::from(&corpus);
    let out = std::env::temp_dir().join(format!("teixml-mut-acc-{}.zip", std::process::id()));
    let t0 = Instant::now();
    let sum = export_mutable(&dir, &out).unwrap();
    let elapsed = t0.elapsed();
    let failed = sum.entries.iter().filter(|e| e.error.is_some()).count();
    eprintln!(
        "MUTABLE ACCEPTANCE export: files={} converted={} failures={} out_bytes={} elapsed_s={:.2}",
        sum.entries.len(),
        sum.documents,
        failed,
        sum.out_bytes,
        elapsed.as_secs_f64()
    );
    for e in sum.entries.iter().filter(|e| e.error.is_some()) {
        eprintln!("  failure: {} — {}", e.rel, e.error.as_deref().unwrap_or(""));
    }
    assert_eq!(sum.entries.len(), sum.documents + failed, "every file accounted for");

    // Text fidelity + annotation budget, per converted document.
    let mut max_annotations = 0usize;
    let mut max_doc = String::new();
    let mut mismatches = Vec::new();
    for e in &sum.entries {
        if e.error.is_some() {
            continue;
        }
        let bytes = std::fs::read(dir.join(&e.rel)).unwrap();
        let root = parse_xml(&bytes).unwrap();
        let doc = build_document(&e.rel, &root);
        let mut nodes = Vec::new();
        root.text_nodes(&mut nodes);
        if non_ws(&doc.plain_text) != non_ws(&nodes.concat()) {
            mismatches.push(e.rel.clone());
        }
        if doc.annotations > max_annotations {
            max_annotations = doc.annotations;
            max_doc = e.rel.clone();
        }
    }
    eprintln!(
        "MUTABLE ACCEPTANCE fidelity: mismatches={} max_annotations={} in {}",
        mismatches.len(),
        max_annotations,
        max_doc
    );
    assert!(mismatches.is_empty(), "text fidelity mismatches: {:?}", &mismatches[..mismatches.len().min(10)]);
    let _ = std::fs::remove_file(&out);
}

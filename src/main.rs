use std::path::{Path, PathBuf};
use std::process::ExitCode;
use teixml_to_mutable::{convert_dir, extract_original, parse_subspace, verify, ChainReader};

fn usage() -> ExitCode {
    eprintln!(
        "teixml-to-mutable 0.1 — TEI-XML -> raw phext\n\n\
         USAGE:\n\
         \x20 convert <input-dir> -o <out.phext>\n\
         \x20 extract <chain.phext> <relative-path> -o <out-file>\n\
         \x20 show    <chain.phext> <$N:coordinate>\n\
         \x20 verify  <chain.phext> [--corpus <input-dir>]"
    );
    ExitCode::from(2)
}

fn opt(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return usage();
    }
    match args[0].as_str() {
        "convert" => {
            let dir = match args.get(1) {
                Some(d) => PathBuf::from(d),
                None => return usage(),
            };
            let out = match opt(&args, "-o") {
                Some(o) => PathBuf::from(o),
                None => return usage(),
            };
            match convert_dir(&dir, &out) {
                Ok(sum) => {
                    let failed = sum.entries.iter().filter(|e| e.error.is_some()).count();
                    println!(
                        "files: {}\nconverted: {}\nfailures: {}\nmembers: {}\nout_bytes: {}",
                        sum.entries.len(),
                        sum.entries.len() - failed,
                        failed,
                        sum.members_written,
                        sum.out_bytes
                    );
                    if failed > 0 {
                        let report = out.with_extension("failures.txt");
                        let mut text = String::new();
                        for e in sum.entries.iter().filter(|e| e.error.is_some()) {
                            let line = format!("{}\t{}\n", e.rel, e.error.as_deref().unwrap_or(""));
                            eprint!("{}", line);
                            text.push_str(&line);
                        }
                        let _ = std::fs::write(&report, text);
                        eprintln!("failure report: {}", report.display());
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("convert failed: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        "extract" => {
            let (chain, rel, out) = match (args.get(1), args.get(2), opt(&args, "-o")) {
                (Some(c), Some(r), Some(o)) => (PathBuf::from(c), r.clone(), PathBuf::from(o)),
                _ => return usage(),
            };
            let reader = match ChainReader::open(&chain) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("open: {}", e);
                    return ExitCode::FAILURE;
                }
            };
            match extract_original(&reader, &rel) {
                Ok(bytes) => {
                    if let Some(parent) = out.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match std::fs::write(&out, &bytes) {
                        Ok(()) => {
                            println!("extracted {} ({} bytes, sha256 verified)", rel, bytes.len());
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("write: {}", e);
                            ExitCode::FAILURE
                        }
                    }
                }
                Err(e) => {
                    eprintln!("extract: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        "show" => {
            let (chain, addr) = match (args.get(1), args.get(2)) {
                (Some(c), Some(a)) => (PathBuf::from(c), a.clone()),
                _ => return usage(),
            };
            let reader = match ChainReader::open(&chain) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("open: {}", e);
                    return ExitCode::FAILURE;
                }
            };
            match parse_subspace(&addr) {
                Ok((universe, coord)) => match reader.get(universe, &coord) {
                    Some(scroll) => {
                        println!("{}", scroll);
                        ExitCode::SUCCESS
                    }
                    None => {
                        eprintln!("no scroll at {}", addr);
                        ExitCode::FAILURE
                    }
                },
                Err(e) => {
                    eprintln!("address: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        "verify" => {
            let chain = match args.get(1) {
                Some(c) => PathBuf::from(c),
                None => return usage(),
            };
            let corpus = opt(&args, "--corpus").map(PathBuf::from);
            match verify(&chain, corpus.as_deref()) {
                Ok(rep) => {
                    println!(
                        "members: {}\nfiles: {}\nfailures: {}\noriginals_verified: {}\nrefs_total: {}\ndangling_refs: {}\nunreachable_universes: {}\ntext_mismatches: {}",
                        rep.members,
                        rep.files,
                        rep.failures,
                        rep.originals_verified,
                        rep.refs_total,
                        rep.dangling_refs.len(),
                        rep.unreachable_universes.len(),
                        rep.text_mismatches.len()
                    );
                    for m in &rep.text_mismatches {
                        eprintln!("text mismatch: {}", m);
                    }
                    let ok = rep.dangling_refs.is_empty()
                        && rep.unreachable_universes.is_empty()
                        && rep.text_mismatches.is_empty()
                        && rep.originals_verified == rep.files;
                    if ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(e) => {
                    eprintln!("verify: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        _ => usage(),
    }
}

// keep Path import used on all targets
#[allow(dead_code)]
fn _t(p: &Path) -> &Path {
    p
}

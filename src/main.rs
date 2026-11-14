use std::path::{Path, PathBuf};
use std::process::ExitCode;
use teixml_to_mutable::mutable::export_mutable;
use teixml_to_mutable::phextura::{
    check_reconstruction, export_phextura_opts, relocate, validate_pair,
};
use teixml_to_mutable::{convert_dir, extract_original, parse_subspace, verify, ChainReader};

fn usage() -> ExitCode {
    eprintln!(
        "teixml-to-mutable 0.3 — TEI-XML -> raw phext / Mutable OS / Phextura\n\n\
         USAGE:\n\
         \x20 convert <input-dir> -o <out.phext>\n\
         \x20 mutable <input-dir> -o <out.zip>\n\
         \x20 phextura <input-dir> -o <out-dir> [--no-vfs]\n\
         \x20 extract <chain.phext> <relative-path> -o <out-file>\n\
         \x20 show    <chain.phext> <$N:coordinate>\n\
         \x20 verify  <chain.phext> [--corpus <input-dir>]\n\
         \x20 verify-phextura <base.phext> <standoff.phext> [--corpus <input-dir>]\n\
         \x20 relocate-phextura <base.phext> <standoff.phext>"
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
        "mutable" => {
            let dir = match args.get(1) {
                Some(d) => PathBuf::from(d),
                None => return usage(),
            };
            let out = match opt(&args, "-o") {
                Some(o) => PathBuf::from(o),
                None => return usage(),
            };
            match export_mutable(&dir, &out) {
                Ok(sum) => {
                    let failed = sum.entries.iter().filter(|e| e.error.is_some()).count();
                    println!(
                        "files: {}\ndocuments: {}\nfailures: {}\nvault_guid: {}\nout_bytes: {}",
                        sum.entries.len(),
                        sum.documents,
                        failed,
                        sum.vault_guid,
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
                    eprintln!("mutable failed: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        "phextura" => {
            let dir = match args.get(1) {
                Some(d) => PathBuf::from(d),
                None => return usage(),
            };
            let out = match opt(&args, "-o") {
                Some(o) => PathBuf::from(o),
                None => return usage(),
            };
            let emit_vfs = !args.iter().any(|a| a == "--no-vfs");
            match export_phextura_opts(&dir, &out, emit_vfs) {
                Ok(sum) => {
                    let failed = sum.entries.iter().filter(|e| e.error.is_some()).count();
                    println!(
                        "files: {}\ndocuments: {}\nfailures: {}\nbase: {} ({} bytes, {} scrolls)\nstandoff: {} ({} bytes, {} scrolls)\nentries: {}\nrefs: {} resolved / {} unresolved / {} external\nexternals: {}\npin: {}",
                        sum.entries.len(),
                        sum.documents,
                        failed,
                        sum.base_path.display(),
                        sum.base_bytes,
                        sum.base_scrolls,
                        sum.standoff_path.display(),
                        sum.standoff_bytes,
                        sum.standoff_scrolls,
                        sum.total_entries,
                        sum.refs.resolved,
                        sum.refs.unresolved,
                        sum.refs.external,
                        sum.externals,
                        sum.pin
                    );
                    match &sum.vfs_path {
                        Some(p) => println!(
                            "vfs: {} ({} bytes, {} scrolls)",
                            p.display(),
                            sum.vfs_bytes,
                            sum.vfs_scrolls
                        ),
                        None => println!("vfs: not emitted (--no-vfs)"),
                    }
                    for e in sum.entries.iter().filter(|e| e.error.is_some()) {
                        eprintln!("{}\t{}", e.rel, e.error.as_deref().unwrap_or(""));
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("phextura failed: {}", e);
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
        "verify-phextura" => {
            let (base, standoff) = match (args.get(1), args.get(2)) {
                (Some(b), Some(s)) => (PathBuf::from(b), PathBuf::from(s)),
                _ => return usage(),
            };
            let corpus = opt(&args, "--corpus").map(PathBuf::from);
            match validate_pair(&base, &standoff) {
                Ok(rep) => {
                    println!(
                        "base_scrolls: {}\nstandoff_scrolls: {}\nbase_checksum_ok: {}\nstandoff_checksum_ok: {}\nkeys_indexed: {}\nentries: {}\nmedia_headers: {}\nexternals_declared: {}\nbare_coords_in_prose: {} (resolvable {})",
                        rep.base_scrolls,
                        rep.standoff_scrolls,
                        rep.base_checksum_ok,
                        rep.standoff_checksum_ok,
                        rep.keys_indexed,
                        rep.entries,
                        rep.media_headers,
                        rep.externals_declared,
                        rep.bare_coords_in_prose,
                        rep.resolvable_bare_coords
                    );
                    for f in &rep.failures {
                        eprintln!("validation failure: {}", f);
                    }
                    let mut ok = rep.ok;
                    if let Some(dir) = corpus {
                        match check_reconstruction(&base, &standoff, &dir) {
                            Ok(r) => {
                                println!(
                                    "recon_files: {}\noriginals_verified: {}\nsegments: {}\nelements: {}\nattributes: {}\ncomments: {}\npis: {}\ndoctypes: {}\nrefs: {} resolved / {} unresolved / {} external\nrecon_mismatches: {}",
                                    r.files,
                                    r.originals_verified,
                                    r.segments,
                                    r.elements,
                                    r.attributes,
                                    r.comments,
                                    r.pis,
                                    r.doctypes,
                                    r.refs_resolved,
                                    r.refs_unresolved,
                                    r.refs_external,
                                    r.mismatch_total
                                );
                                for m in &r.mismatches {
                                    eprintln!("recon mismatch: {}", m);
                                }
                                ok = ok && r.ok;
                            }
                            Err(e) => {
                                eprintln!("verify-phextura: {}", e);
                                return ExitCode::FAILURE;
                            }
                        }
                    }
                    if ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(e) => {
                    eprintln!("verify-phextura: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        "relocate-phextura" => {
            let (base, standoff) = match (args.get(1), args.get(2)) {
                (Some(b), Some(s)) => (PathBuf::from(b), PathBuf::from(s)),
                _ => return usage(),
            };
            match relocate(&base, &standoff) {
                Ok(rep) => {
                    println!(
                        "entries: {}\nexact: {}\nrelocated_verified: {}\nrelocated_moved: {}\nanchor_lost: {}\nambiguous: {}",
                        rep.total,
                        rep.exact,
                        rep.relocated_verified,
                        rep.relocated_moved,
                        rep.lost.len(),
                        rep.ambiguous.len()
                    );
                    for d in rep.lost.iter().chain(rep.ambiguous.iter()).take(20) {
                        eprintln!("detached {} {}: {:?}", d.key, d.class, d.quoted);
                    }
                    if rep.lost.is_empty() && rep.ambiguous.is_empty() {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(e) => {
                    eprintln!("relocate-phextura: {}", e);
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

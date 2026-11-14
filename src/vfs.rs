//! PhextVFS image writer — ruling D6, decided "Both" by Will
//! (2026-11-14 03:04): the `phextura` emission produces, alongside the
//! corpus pair, a phext-mode Mutable Cavern image `cavern.phext` holding
//! the pair as its files.
//!
//! The format is Mutable's own, taken from mutable-os `src/phext/vfs.ts`
//! (+ `lattice.ts`, `coordinate.ts`) on main — this module writes exactly
//! the state Mutable's `PhextVFS` writer reaches after create + writeFile
//! + flush, so Mutable's reader opens the image and its open-time L9
//! checksum verification passes:
//!
//! - Strata are library arms; the pair lives in stratum 1 (documents) at
//!   the stratum root: `/<name>.phext`, `/<name>.standoff.phext`.
//! - The stratum root index scroll (1.1.1/1.1.1/1.1.1) holds JSON
//!   `{v: 1, nextSlot, entries}`; child slots start at 2 and are never
//!   reused (a fresh image allocates sequentially: 2, 3, …).
//! - File content lives in chunk scrolls: slot on the shelf arm, part
//!   arm 1, 1-based chunk index on the scroll arm.
//! - The pair files are phext text, so they contain phext dimension
//!   break bytes and CANNOT be stored in the VFS's text format (vfs.ts
//!   `assertTextPayload` rejects break bytes). They are stored in the
//!   VFS binary format: raw chunks of `3*floor(chunkSize/4)` bytes, each
//!   base64-encoded as its own scroll. Read-back concatenates the
//!   decoded chunks and is byte-identical to the standalone files.
//! - Library 9: home scroll is the manifest
//!   `{format: "mutable-phext-vfs", version: 1, chunkSize, checksumScrolls,
//!   scrolls}`; the checksum series behind it (scroll arm 2, 3, …) holds
//!   JSON maps of coordinate → SHA-256 of that scroll's bytes, keys in
//!   string-sorted order, 512 entries per scroll, covering every
//!   populated scroll except the checksum series itself.
//!
//! phext serialization itself is libphext's (`canonical_bytes`), as
//! everywhere in this crate; nothing here parses or emits break bytes.

use crate::phextura::{canonical_bytes, C9};
use crate::sha256_hex;
use libphext::phext;
use std::collections::HashMap;

/// Mutable's DEFAULT_CHUNK_SIZE (vfs.ts).
pub const VFS_CHUNK_SIZE: usize = 65536;
/// Mutable's CHECKSUMS_PER_SCROLL (vfs.ts).
const CHECKSUMS_PER_SCROLL: usize = 512;
/// Mutable's FIRST_SLOT (vfs.ts): slot 1 is the directory's own index.
const FIRST_SLOT: u32 = 2;
/// The documents stratum (VFS_STRATA.documents).
const STRATUM_DOCUMENTS: u32 = 1;
/// The VFS index stratum (VFS_STRATA.index).
const STRATUM_INDEX: u32 = 9;

#[derive(Debug, Clone, PartialEq)]
pub struct VfsImageInfo {
    pub bytes: usize,
    pub scrolls: usize,
    pub files: usize,
    pub chunks: usize,
    pub checksum_scrolls: usize,
}

fn coord(levels: [u32; 9]) -> C9 {
    C9::new(
        (levels[0], levels[1], levels[2]),
        (levels[3], levels[4], levels[5]),
        (levels[6], levels[7], levels[8]),
    )
}

fn root_index_coord() -> C9 {
    coord([STRATUM_DOCUMENTS, 1, 1, 1, 1, 1, 1, 1, 1])
}

fn chunk_coord(slot: u32, chunk_index: u32) -> C9 {
    coord([STRATUM_DOCUMENTS, slot, 1, 1, 1, 1, 1, 1, chunk_index])
}

fn manifest_coord() -> C9 {
    coord([STRATUM_INDEX, 1, 1, 1, 1, 1, 1, 1, 1])
}

fn checksum_coord(series_index: u32) -> C9 {
    coord([STRATUM_INDEX, 1, 1, 1, 1, 1, 1, 1, series_index + 2])
}

/// Standard base64 (RFC 4648, padded) — the encoding Mutable's
/// `Buffer.toString("base64")` produces and its reader decodes per chunk.
pub fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for triple in bytes.chunks(3) {
        let b0 = triple[0] as u32;
        let b1 = *triple.get(1).unwrap_or(&0) as u32;
        let b2 = *triple.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if triple.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if triple.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// JSON string escaping with JSON.stringify semantics (the index and
/// manifest scrolls are consumed by Mutable's `JSON.parse`).
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Build the `cavern.phext` image holding `files` (name, bytes) in the
/// given order at the documents-stratum root, in the VFS binary format.
/// Returns the image bytes and its accounting.
pub fn build_cavern_image(files: &[(&str, &[u8])]) -> (Vec<u8>, VfsImageInfo) {
    let raw_chunk = 3 * (VFS_CHUNK_SIZE / 4);
    let mut scrolls: Vec<(C9, String)> = Vec::new();
    let mut entries_json = String::new();
    let mut total_chunks = 0usize;
    for (i, (name, bytes)) in files.iter().enumerate() {
        let slot = FIRST_SLOT + i as u32;
        let chunks: Vec<&[u8]> = bytes.chunks(raw_chunk).collect();
        for (ci, chunk) in chunks.iter().enumerate() {
            scrolls.push((chunk_coord(slot, ci as u32 + 1), base64_encode(chunk)));
        }
        total_chunks += chunks.len();
        if i > 0 {
            entries_json.push(',');
        }
        // Key order mirrors the FileIndexEntry literal in vfs.ts
        // writeFile: kind, slot, format, size, chunks, sha256.
        entries_json.push_str(&format!(
            "\"{}\":{{\"kind\":\"file\",\"slot\":{},\"format\":\"binary\",\"size\":{},\"chunks\":{},\"sha256\":\"{}\"}}",
            json_escape(name),
            slot,
            bytes.len(),
            chunks.len(),
            sha256_hex(bytes)
        ));
    }
    let next_slot = FIRST_SLOT + files.len() as u32;
    let index_text = format!(
        "{{\"v\":1,\"nextSlot\":{},\"entries\":{{{}}}}}",
        next_slot, entries_json
    );
    scrolls.push((root_index_coord(), index_text));

    // Covered scrolls: everything populated except the checksum series
    // (not yet written) — the index, the chunks, and the manifest.
    let covered = scrolls.len() + 1;
    let checksum_scrolls = (covered + CHECKSUMS_PER_SCROLL - 1) / CHECKSUMS_PER_SCROLL;
    let checksum_scrolls = checksum_scrolls.max(1);
    let manifest_text = format!(
        "{{\"format\":\"mutable-phext-vfs\",\"version\":1,\"chunkSize\":{},\"checksumScrolls\":{},\"scrolls\":{}}}",
        VFS_CHUNK_SIZE, checksum_scrolls, covered
    );
    scrolls.push((manifest_coord(), manifest_text));

    // The L9 checksum series: coordinate → SHA-256 of the scroll's
    // bytes, keys string-sorted (vfs.ts sorts Object.keys), 512 per
    // scroll.
    let mut sums: Vec<(String, String)> = scrolls
        .iter()
        .map(|(c, text)| (c.addr(), sha256_hex(text.as_bytes())))
        .collect();
    sums.sort();
    for (si, slice) in sums.chunks(CHECKSUMS_PER_SCROLL).enumerate() {
        let mut text = String::from("{");
        for (j, (addr, sum)) in slice.iter().enumerate() {
            if j > 0 {
                text.push(',');
            }
            text.push_str(&format!("\"{}\":\"{}\"", addr, sum));
        }
        text.push('}');
        scrolls.push((checksum_coord(si as u32), text));
    }

    let scroll_count = scrolls.len();
    let map: HashMap<phext::Coordinate, String> =
        scrolls.into_iter().map(|(c, t)| (c.phext(), t)).collect();
    let bytes = canonical_bytes(&map);
    let info = VfsImageInfo {
        bytes: bytes.len(),
        scrolls: scroll_count,
        files: files.len(),
        chunks: total_chunks,
        checksum_scrolls,
    };
    (bytes, info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(&[0xfb, 0xff, 0xfe]), "+//+");
    }

    #[test]
    fn json_escape_matches_stringify() {
        assert_eq!(json_escape("plain.phext"), "plain.phext");
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("a\nb\u{01}"), "a\\nb\\u0001");
    }

    fn base64_decode(text: &str) -> Vec<u8> {
        let mut vals = Vec::with_capacity(text.len());
        for ch in text.bytes() {
            vals.push(match ch {
                b'A'..=b'Z' => ch - b'A',
                b'a'..=b'z' => ch - b'a' + 26,
                b'0'..=b'9' => ch - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => 64,
                other => panic!("bad base64 byte {}", other),
            });
        }
        let mut out = Vec::new();
        for quad in vals.chunks(4) {
            let n = ((quad[0] as u32) << 18)
                | ((quad[1] as u32) << 12)
                | ((quad[2] as u32 & 63) << 6)
                | (quad[3] as u32 & 63);
            out.push((n >> 16) as u8);
            if quad[2] != 64 {
                out.push((n >> 8) as u8);
            }
            if quad[3] != 64 {
                out.push(n as u8);
            }
        }
        out
    }

    /// Extract a flat JSON object's string→string pairs (the checksum
    /// series' shape) without a JSON dependency: keys and values here
    /// are coordinates and hex digests, neither contains escapes.
    fn parse_flat_object(text: &str) -> Vec<(String, String)> {
        let inner = text.strip_prefix('{').unwrap().strip_suffix('}').unwrap();
        if inner.is_empty() {
            return Vec::new();
        }
        inner
            .split(',')
            .map(|pair| {
                let (k, v) = pair.split_once(':').unwrap();
                (
                    k.trim_matches('"').to_string(),
                    v.trim_matches('"').to_string(),
                )
            })
            .collect()
    }

    /// Read a file back the way Mutable's reader does, and verify every
    /// covered scroll against the L9 checksum series (the open-time
    /// integrity check, re-derived independently here).
    fn read_back(image: &[u8], name: &str) -> Vec<u8> {
        let text = std::str::from_utf8(image).unwrap();
        let map = phext::explode(text);
        let manifest = map.get(&manifest_coord().phext()).unwrap().clone();
        let series: usize = parse_flat_object(&manifest)
            .into_iter()
            .find(|(k, _)| k == "checksumScrolls")
            .map(|(_, v)| v.parse().unwrap())
            .unwrap();
        let declared: usize = parse_flat_object(&manifest)
            .into_iter()
            .find(|(k, _)| k == "scrolls")
            .map(|(_, v)| v.parse().unwrap())
            .unwrap();
        let mut recorded: HashMap<String, String> = HashMap::new();
        for si in 0..series {
            let slice = map.get(&checksum_coord(si as u32).phext()).unwrap();
            for (k, v) in parse_flat_object(slice) {
                recorded.insert(k, v);
            }
        }
        let mut covered = 0usize;
        for (c9, scroll) in scrolls_of(&map) {
            let addr = c9.addr();
            let is_series = c9.z.0 == 9 && c9 != manifest_coord();
            if is_series {
                continue;
            }
            covered += 1;
            assert_eq!(
                recorded.get(&addr).map(|s| s.as_str()),
                Some(sha256_hex(scroll.as_bytes()).as_str()),
                "checksum for {}",
                addr
            );
        }
        assert_eq!(covered, declared);
        assert_eq!(recorded.len(), covered);
        // File read-back via the root index: locate the entry by name.
        let index = map.get(&root_index_coord().phext()).unwrap().clone();
        let slot = find_number(&index, name, "slot");
        let chunks = find_number(&index, name, "chunks");
        let size = find_number(&index, name, "size");
        let mut out = Vec::new();
        for ci in 1..=chunks {
            let scroll = map.get(&chunk_coord(slot, ci).phext()).unwrap();
            out.extend_from_slice(&base64_decode(scroll));
        }
        assert_eq!(out.len(), size as usize);
        out
    }

    fn scrolls_of(map: &HashMap<phext::Coordinate, String>) -> Vec<(C9, String)> {
        map.iter()
            .map(|(c, t)| {
                let s = format!("{:?}", c);
                let _ = s;
                (coord_of_phext(c), t.clone())
            })
            .collect()
    }

    fn coord_of_phext(c: &phext::Coordinate) -> C9 {
        // libphext Coordinates format via Display in tests elsewhere in
        // this crate; parse the canonical string form back to C9.
        C9::parse(&c.to_string()).expect("coordinate string parses")
    }

    fn find_number(index: &str, name: &str, field: &str) -> u32 {
        let name_at = index.find(&format!("\"{}\"", name)).unwrap();
        let rest = &index[name_at..];
        let field_at = rest.find(&format!("\"{}\":", field)).unwrap();
        let rest = &rest[field_at + field.len() + 3..];
        let end = rest
            .find(|ch: char| !ch.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse().unwrap()
    }

    #[test]
    fn small_image_round_trips() {
        let a = b"hello phext\x17world".to_vec();
        let b: Vec<u8> = (0..120_000u32).map(|i| (i % 251) as u8).collect();
        let (image, info) = build_cavern_image(&[("a.phext", &a), ("a.standoff.phext", &b)]);
        assert_eq!(info.files, 2);
        // a: 1 chunk; b: ceil(120000/49152) = 3 chunks
        assert_eq!(info.chunks, 4);
        assert_eq!(read_back(&image, "a.phext"), a);
        assert_eq!(read_back(&image, "a.standoff.phext"), b);
    }

    #[test]
    fn empty_file_has_zero_chunks() {
        let (image, info) = build_cavern_image(&[("empty.phext", &[])]);
        assert_eq!(info.chunks, 0);
        assert_eq!(read_back(&image, "empty.phext"), Vec::<u8>::new());
    }
}

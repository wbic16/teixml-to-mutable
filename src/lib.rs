//! teixml-to-mutable — TEI-XML → raw phext (stage 0.1, SPEC 0.1 v3),
//! Mutable OS native Caverns (stage 0.2, see `mutable`), and Phextura
//! corpora (stage 0.3, see `phextura`). Task 5.4.6/5.5.5/5.6.5.
//!
//! All phext parsing/serialization goes through libphext-rs 0.6 (the reference
//! implementation). This crate never parses phext delimiters itself, except the
//! top-level chain byte scan in the reader, which is cross-checked byte-for-byte
//! against libphext's `parse_chains` on every open.

pub mod mutable;
pub mod phextura;
pub mod segment;
pub mod vfs;

use libphext::{binary, phext};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const FORMAT_VERSION: &str = "0.1";

/// Bytes that are phext structure breaks; a text original may never contain them.
const PHEXT_BREAK_BYTES: &[u8] = &[
    0x01, 0x02, 0x03, 0x17, 0x18, 0x19, 0x1A, 0x1C, 0x1D, 0x1E, 0x1F,
];

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub fn coord(scroll: usize) -> phext::Coordinate {
    phext::to_coordinate(&format!("1.1.1/1.1.1/1.1.{}", scroll))
}

// ---------------------------------------------------------------------------
// XML tree (built with quick-xml, a streaming parser; the tree lives per-file)

#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Text(String),
    Elem(Element),
    /// XML comment, text verbatim (stage 0.3 model capture, ruling D3).
    Comment(String),
    /// Processing instruction (stage 0.3 model capture, ruling D3).
    Pi { target: String, data: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Element {
    pub ns: String,
    pub name: String,
    /// (qualified name as written, value) in document order
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Node>,
}

impl Element {
    pub fn is_container(&self) -> bool {
        self.children.iter().any(|c| matches!(c, Node::Elem(_)))
    }
    /// All text nodes of this element's subtree, in document order.
    /// Comments and PIs are not text nodes and never appear here.
    pub fn text_nodes(&self, out: &mut Vec<String>) {
        for c in &self.children {
            match c {
                Node::Text(t) => out.push(t.clone()),
                Node::Elem(e) => e.text_nodes(out),
                Node::Comment(_) | Node::Pi { .. } => {}
            }
        }
    }
}

fn unescape(s: &str) -> Result<String, String> {
    quick_xml::escape::unescape(s)
        .map(|c| c.into_owned())
        .map_err(|e| format!("unescape: {}", e))
}

/// A document type declaration, as written (stage 0.3, ruling D3).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Doctype {
    pub name: String,
    pub public_id: Option<String>,
    pub system_id: Option<String>,
    /// The internal subset verbatim (text between `[` and the closing `]`),
    /// when the declaration carries one.
    pub internal_subset: Option<String>,
}

/// The full parse of one XML document: root element tree plus the prolog
/// and epilog material (comments, PIs) and the DOCTYPE, which live outside
/// the root element but are part of the document (stage 0.3, ruling D3).
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedDocument {
    pub root: Element,
    pub doctype: Option<Doctype>,
    pub prolog: Vec<Node>,
    pub epilog: Vec<Node>,
}

/// Extract the internal subset of a DOCTYPE declaration: the verbatim text
/// between the first `[` outside quotes and its closing `]`, where the
/// scan is aware of quoted strings, comments, and nested declarations
/// (a `]` inside any of those does not close the subset).
fn extract_internal_subset(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut quote: Option<u8> = None;
    let mut start: Option<usize> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => {
                if b == b'"' || b == b'\'' {
                    quote = Some(b);
                } else if b == b'[' {
                    start = Some(i);
                    break;
                }
            }
        }
        i += 1;
    }
    let start = start?;
    let mut j = start + 1;
    let mut quote: Option<u8> = None;
    let mut in_comment = false;
    let mut in_decl = false;
    while j < bytes.len() {
        if in_comment {
            if bytes[j..].starts_with(b"-->") {
                in_comment = false;
                j += 3;
            } else {
                j += 1;
            }
            continue;
        }
        match quote {
            Some(q) => {
                if bytes[j] == q {
                    quote = None;
                }
                j += 1;
            }
            None => {
                if bytes[j..].starts_with(b"<!--") {
                    in_comment = true;
                    j += 4;
                } else if bytes[j] == b'"' || bytes[j] == b'\'' {
                    quote = Some(bytes[j]);
                    j += 1;
                } else if bytes[j] == b'<' {
                    in_decl = true;
                    j += 1;
                } else if bytes[j] == b'>' {
                    in_decl = false;
                    j += 1;
                } else if bytes[j] == b']' && !in_decl {
                    return Some(raw[start + 1..j].to_string());
                } else {
                    j += 1;
                }
            }
        }
    }
    None
}

/// Recover the raw inner text of the document's `<!DOCTYPE ...>`
/// declaration from the prolog bytes, or None when there is none.
/// quick-xml 0.38's DocType event truncates at the first `>` inside an
/// internal subset (measured: an ENTITY value containing `>` ends the
/// event mid-subset), so the declaration is scanned here with quote,
/// comment, and subset awareness. Returns the inner text and the
/// declaration's byte span in the scanned text — the span matters
/// because the reader, having truncated its DocType event, re-emits
/// the rest of the subset (e.g. a subset comment) as ordinary events,
/// which the span lets the parser suppress.
fn raw_doctype_inner(text: &str) -> Option<(String, usize, usize)> {
    let bytes = text.as_bytes();
    let find = |from: usize, needle: &[u8]| -> Option<usize> {
        if from > bytes.len() {
            return None;
        }
        bytes[from..]
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| p + from)
    };
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"<!--") {
            i = find(i, b"-->")? + 3;
        } else if bytes[i..].starts_with(b"<?") {
            i = find(i, b"?>")? + 2;
        } else if bytes[i..].starts_with(b"<!DOCTYPE") {
            let start = i + "<!DOCTYPE".len();
            let end = doctype_end(text, start)?;
            return Some((text[start..end].to_string(), i, end + 1));
        } else if bytes[i] == b'<' {
            return None; // the root element begins; no doctype
        } else {
            i += 1;
        }
    }
    None
}

/// The offset of the `>` that closes a DOCTYPE declaration whose inner
/// text starts at `start`: a `>` outside quotes, comments, the internal
/// subset, and any declaration inside the subset.
fn doctype_end(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut j = start;
    let mut quote: Option<u8> = None;
    let mut in_comment = false;
    let mut in_subset = false;
    let mut in_decl = false;
    while j < bytes.len() {
        if in_comment {
            if bytes[j..].starts_with(b"-->") {
                in_comment = false;
                j += 3;
            } else {
                j += 1;
            }
            continue;
        }
        match quote {
            Some(q) => {
                if bytes[j] == q {
                    quote = None;
                }
                j += 1;
            }
            None => {
                if bytes[j..].starts_with(b"<!--") {
                    in_comment = true;
                    j += 4;
                } else if bytes[j] == b'"' || bytes[j] == b'\'' {
                    quote = Some(bytes[j]);
                    j += 1;
                } else if bytes[j] == b'[' {
                    in_subset = true;
                    j += 1;
                } else if bytes[j] == b']' && !in_decl {
                    in_subset = false;
                    j += 1;
                } else if bytes[j] == b'<' && in_subset {
                    in_decl = true;
                    j += 1;
                } else if bytes[j] == b'>' {
                    if in_decl {
                        in_decl = false;
                        j += 1;
                    } else if !in_subset {
                        return Some(j);
                    } else {
                        j += 1;
                    }
                } else {
                    j += 1;
                }
            }
        }
    }
    None
}

/// Parse the inner text of a `<!DOCTYPE ...>` declaration (everything
/// between `<!DOCTYPE` and the closing `>`).
pub fn parse_doctype(raw: &str) -> Doctype {
    let mut dt = Doctype::default();
    let s = raw.trim_start();
    // root element name: up to whitespace or '['
    let name_end = s
        .find(|c: char| c.is_whitespace() || c == '[')
        .unwrap_or(s.len());
    dt.name = s[..name_end].to_string();
    // tokenize the rest outside the subset: words and quoted strings
    let rest = &s[name_end..];
    let subset_at = {
        let mut quote: Option<char> = None;
        let mut found = None;
        for (i, c) in rest.char_indices() {
            match quote {
                Some(q) => {
                    if c == q {
                        quote = None;
                    }
                }
                None => {
                    if c == '"' || c == '\'' {
                        quote = Some(c);
                    } else if c == '[' {
                        found = Some(i);
                        break;
                    }
                }
            }
        }
        found
    };
    let head = match subset_at {
        Some(i) => &rest[..i],
        None => rest,
    };
    let mut tokens: Vec<(bool, String)> = Vec::new(); // (is_quoted, text)
    let mut chars = head.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else if c == '"' || c == '\'' {
            chars.next();
            let mut val = String::new();
            for c2 in chars.by_ref() {
                if c2 == c {
                    break;
                }
                val.push(c2);
            }
            tokens.push((true, val));
        } else {
            let mut w = String::new();
            while let Some(&c2) = chars.peek() {
                if c2.is_whitespace() {
                    break;
                }
                w.push(c2);
                chars.next();
            }
            tokens.push((false, w));
        }
    }
    let mut i = 0usize;
    while i < tokens.len() {
        if !tokens[i].0 && tokens[i].1.eq_ignore_ascii_case("PUBLIC") {
            if i + 1 < tokens.len() && tokens[i + 1].0 {
                dt.public_id = Some(tokens[i + 1].1.clone());
            }
            if i + 2 < tokens.len() && tokens[i + 2].0 {
                dt.system_id = Some(tokens[i + 2].1.clone());
            }
            break;
        }
        if !tokens[i].0 && tokens[i].1.eq_ignore_ascii_case("SYSTEM") {
            if i + 1 < tokens.len() && tokens[i + 1].0 {
                dt.system_id = Some(tokens[i + 1].1.clone());
            }
            break;
        }
        i += 1;
    }
    dt.internal_subset = extract_internal_subset(raw);
    dt
}

/// Parse one XML document (bytes) into an Element tree.
/// Namespace URIs are resolved with a prefix-scope stack; attributes keep
/// their qualified names as written. Since stage 0.3 the tree also carries
/// comments and PIs as nodes; the 0.1/0.2 emitters skip them (their forms
/// never represented comments/PIs — the original is preserved verbatim).
pub fn parse_xml(bytes: &[u8]) -> Result<Element, String> {
    Ok(parse_xml_full(bytes)?.root)
}

/// Parse one XML document into root tree + prolog/epilog + DOCTYPE.
pub fn parse_xml_full(bytes: &[u8]) -> Result<ParsedDocument, String> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    let mut buf: Vec<u8> = Vec::new();
    let mut stack: Vec<Element> = Vec::new();
    let mut scopes: Vec<HashMap<String, String>> = Vec::new();
    let mut root: Option<Element> = None;
    // The DOCTYPE comes from the raw prolog bytes (see raw_doctype_inner);
    // the reader's own DocType event is only a fallback.
    let raw_doctype = raw_doctype_inner(&String::from_utf8_lossy(bytes));
    let doctype_span: Option<(usize, usize)> =
        raw_doctype.as_ref().map(|(_, s, e)| (*s, *e));
    let mut doctype: Option<Doctype> =
        raw_doctype.map(|(raw, _, _)| parse_doctype(&raw));
    let mut prolog: Vec<Node> = Vec::new();
    let mut epilog: Vec<Node> = Vec::new();

    fn resolve(qname: &str, own: &HashMap<String, String>, scopes: &[HashMap<String, String>]) -> String {
        let prefix = match qname.split_once(':') {
            Some((p, _l)) => p,
            None => "",
        };
        if let Some(uri) = own.get(prefix) {
            return uri.clone();
        }
        for scope in scopes.iter().rev() {
            if let Some(uri) = scope.get(prefix) {
                return uri.clone();
            }
        }
        String::new()
    }

    fn make_element(
        e: &quick_xml::events::BytesStart,
        scopes: &[HashMap<String, String>],
    ) -> Result<(Element, HashMap<String, String>), String> {
        let qname = String::from_utf8_lossy(e.name().as_ref()).into_owned();
        let mut attrs: Vec<(String, String)> = Vec::new();
        let mut own_scope: HashMap<String, String> = HashMap::new();
        for attr in e.attributes() {
            let attr = attr.map_err(|err| format!("attribute: {}", err))?;
            let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
            let raw = String::from_utf8_lossy(&attr.value).into_owned();
            let value = unescape(&raw)?;
            if key == "xmlns" {
                own_scope.insert(String::new(), value.clone());
            } else if let Some(prefix) = key.strip_prefix("xmlns:") {
                own_scope.insert(prefix.to_string(), value.clone());
            }
            attrs.push((key, value));
        }
        let ns = resolve(&qname, &own_scope, scopes);
        let local = qname
            .split_once(':')
            .map(|(_p, l)| l.to_string())
            .unwrap_or_else(|| qname.clone());
        Ok((
            Element { ns, name: local, attrs, children: Vec::new() },
            own_scope,
        ))
    }

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let (el, own) = make_element(&e, &scopes)?;
                scopes.push(own);
                stack.push(el);
            }
            Ok(Event::Empty(e)) => {
                let (el, _own) = make_element(&e, &scopes)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Elem(el)),
                    None => {
                        if root.is_some() {
                            return Err("multiple root elements".into());
                        }
                        root = Some(el);
                    }
                }
            }
            Ok(Event::End(_)) => {
                scopes.pop();
                let el = stack.pop().ok_or("end tag without start tag")?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Elem(el)),
                    None => {
                        if root.is_some() {
                            return Err("multiple root elements".into());
                        }
                        root = Some(el);
                    }
                }
            }
            Ok(Event::Text(e)) => {
                let raw = String::from_utf8_lossy(&e).into_owned();
                let text = unescape(&raw)?;
                if let Some(parent) = stack.last_mut() {
                    if !text.is_empty() {
                        parent.children.push(Node::Text(text));
                    }
                }
            }
            Ok(Event::CData(e)) => {
                let text = String::from_utf8_lossy(&e).into_owned();
                if let Some(parent) = stack.last_mut() {
                    if !text.is_empty() {
                        parent.children.push(Node::Text(text));
                    }
                }
            }
            Ok(Event::Comment(e)) => {
                let in_doctype = doctype_span.map_or(false, |(s, e)| {
                    let pos = reader.buffer_position() as usize;
                    pos > s && pos <= e
                });
                if in_doctype {
                    // an artifact of the reader's truncated DocType
                    // event (a comment inside the internal subset),
                    // not a document comment
                } else if let Some(parent) = stack.last_mut() {
                    parent.children.push(Node::Comment(String::from_utf8_lossy(&e).into_owned()));
                } else if root.is_none() {
                    prolog.push(Node::Comment(String::from_utf8_lossy(&e).into_owned()));
                } else {
                    epilog.push(Node::Comment(String::from_utf8_lossy(&e).into_owned()));
                }
            }
            Ok(Event::PI(e)) => {
                let in_doctype = doctype_span.map_or(false, |(s, e)| {
                    let pos = reader.buffer_position() as usize;
                    pos > s && pos <= e
                });
                if in_doctype {
                    // as for comments: a subset artifact, not a PI
                } else if let Some(parent) = stack.last_mut() {
                    parent.children.push(Node::Pi {
                        target: String::from_utf8_lossy(e.target()).into_owned(),
                        data: String::from_utf8_lossy(e.content()).into_owned(),
                    });
                } else if root.is_none() {
                    prolog.push(Node::Pi {
                        target: String::from_utf8_lossy(e.target()).into_owned(),
                        data: String::from_utf8_lossy(e.content()).into_owned(),
                    });
                } else {
                    epilog.push(Node::Pi {
                        target: String::from_utf8_lossy(e.target()).into_owned(),
                        data: String::from_utf8_lossy(e.content()).into_owned(),
                    });
                }
            }
            Ok(Event::DocType(e)) => {
                if doctype.is_none() {
                    doctype = Some(parse_doctype(&String::from_utf8_lossy(&e)));
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => { /* XML declarations and anything else: not represented */ }
            Err(e) => return Err(format!("xml: {}", e)),
        }
        buf.clear();
    }
    if !stack.is_empty() {
        return Err("unclosed elements at EOF".into());
    }
    let root = root.ok_or_else(|| "no root element".to_string())?;
    Ok(ParsedDocument { root, doctype, prolog, epilog })
}

// ---------------------------------------------------------------------------
// Conversion (SPEC 0.1 v3: one chain per directory, $1 = index + originals)

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StorageClass {
    Text,
    Binary,
}
impl StorageClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            StorageClass::Text => "text",
            StorageClass::Binary => "binary",
        }
    }
}

pub fn classify(bytes: &[u8]) -> StorageClass {
    match std::str::from_utf8(bytes) {
        Ok(_) if !bytes.iter().any(|b| PHEXT_BREAK_BYTES.contains(b)) => StorageClass::Text,
        _ => StorageClass::Binary,
    }
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub rel: String,
    pub sha256: String,
    pub size: usize,
    pub class: StorageClass,
    /// scroll number (1-based, linear scroll axis in $1) holding the original
    pub original_scroll: usize,
    pub first_universe: Option<usize>,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct ConversionSummary {
    pub entries: Vec<FileEntry>,
    pub members_written: usize,
    pub out_bytes: u64,
}

pub fn collect_xml_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out: Vec<PathBuf> = Vec::new();
    fn walk(d: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(d)
            .map_err(|e| format!("read_dir {}: {}", d.display(), e))?
            .filter_map(|r| r.ok().map(|e| e.path()))
            .collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                walk(&p, out)?;
            } else if p
                .extension()
                .map(|x| x.to_string_lossy().eq_ignore_ascii_case("xml"))
                .unwrap_or(false)
            {
                out.push(p);
            }
        }
        Ok(())
    }
    walk(dir, &mut out)?;
    out.sort_by(|a, b| rel_of(dir, a).cmp(&rel_of(dir, b)));
    Ok(out)
}

pub fn rel_of(base: &Path, p: &Path) -> String {
    p.strip_prefix(base)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

fn count_universes(e: &Element) -> usize {
    // every container element gets a universe; a leaf root still gets one
    fn containers(e: &Element) -> usize {
        let mut n = if e.is_container() { 1 } else { 0 };
        for c in &e.children {
            if let Node::Elem(ch) = c {
                n += containers(ch);
            }
        }
        n
    }
    containers(e).max(1)
}

/// Streaming chain writer (WAL write path): members are appended in order,
/// previously written bytes are never touched; the chain-close byte is
/// written last. Byte layout is identical to libphext `Chain::serialize`
/// (verified by a test).
pub struct ChainWriter {
    w: std::io::BufWriter<std::fs::File>,
    pub written: usize,
}

impl ChainWriter {
    pub fn create(path: &Path) -> Result<ChainWriter, String> {
        let f = std::fs::File::create(path).map_err(|e| format!("create {}: {}", path.display(), e))?;
        Ok(ChainWriter { w: std::io::BufWriter::new(f), written: 0 })
    }
    pub fn write_member(&mut self, member: &str) -> Result<(), String> {
        if self.written > 0 {
            self.w.write_all(&[phext::CHAIN_BREAK_U8]).map_err(|e| e.to_string())?;
        }
        self.w.write_all(member.as_bytes()).map_err(|e| e.to_string())?;
        self.written += 1;
        Ok(())
    }
    pub fn close(mut self) -> Result<(), String> {
        self.w.write_all(&[phext::CHAIN_CLOSE_U8]).map_err(|e| e.to_string())?;
        self.w.flush().map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Append one member universe to an existing closed chain (WAL append):
/// every previously written member byte is left untouched; only the old
/// chain-close byte is overwritten by the separator+member+close sequence.
pub fn append_member(path: &Path, member: &str) -> Result<(), String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    let len = f.metadata().map_err(|e| e.to_string())?.len();
    if len == 0 {
        return Err("append_member: empty file".into());
    }
    let mut last = [0u8; 1];
    f.seek(SeekFrom::Start(len - 1)).map_err(|e| e.to_string())?;
    f.read_exact(&mut last).map_err(|e| e.to_string())?;
    if last[0] != phext::CHAIN_CLOSE_U8 {
        return Err("append_member: chain is not closed".into());
    }
    f.seek(SeekFrom::Start(len - 1)).map_err(|e| e.to_string())?;
    f.write_all(&[phext::CHAIN_BREAK_U8]).map_err(|e| e.to_string())?;
    f.write_all(member.as_bytes()).map_err(|e| e.to_string())?;
    f.write_all(&[phext::CHAIN_CLOSE_U8]).map_err(|e| e.to_string())?;
    f.flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn push_element_header(scrolls: &mut Vec<String>, e: &Element) {
    if e.ns.is_empty() {
        scrolls.push(format!("@element {}", e.name));
    } else {
        scrolls.push(format!("@element {{{}}} {}", e.ns, e.name));
    }
    for (k, v) in &e.attrs {
        scrolls.push(format!("@attr {}", k));
        scrolls.push(format!("@value\n{}", v));
    }
}

fn build_index_scroll(entries: &[FileEntry], failures: &[(String, String)]) -> String {
    let mut s = String::new();
    s.push_str(&format!("teixml-to-mutable chain index\nformat\t{}\n", FORMAT_VERSION));
    s.push_str(&format!("files\t{}\n", entries.len()));
    s.push_str(&format!(
        "converted\t{}\n",
        entries.iter().filter(|e| e.error.is_none()).count()
    ));
    s.push_str(&format!("failures\t{}\n", failures.len()));
    let floor = if entries.is_empty() { 1 } else { 1 + entries.len() };
    s.push_str(&format!("floor\t{}\n", coord(floor).to_string()));
    s.push_str("path\tsha256\tsize\tclass\tcoord\tuniverse\n");
    for e in entries {
        let uni = e
            .first_universe
            .map(|n| format!("${}", n))
            .unwrap_or_else(|| "-".to_string());
        s.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            e.rel,
            e.sha256,
            e.size,
            e.class.as_str(),
            coord(e.original_scroll).to_string(),
            uni
        ));
    }
    if !failures.is_empty() {
        s.push_str("failures:\n");
        for (rel, err) in failures {
            let clean: String = err.chars().map(|c| if c == '\t' || c == '\n' { ' ' } else { c }).collect();
            s.push_str(&format!("{}\t{}\n", rel, clean));
        }
    }
    s
}

pub fn convert_dir(dir: &Path, out: &Path) -> Result<ConversionSummary, String> {
    let files = collect_xml_files(dir)?;
    // ---- pass 1: scan, hash, classify, parse, plan universe numbering
    let mut entries: Vec<FileEntry> = Vec::new();
    let mut failures: Vec<(String, String)> = Vec::new();
    let mut next_universe = 2usize; // $1 is universe 1
    for (i, path) in files.iter().enumerate() {
        let rel = rel_of(dir, path);
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        let class = classify(&bytes);
        let mut entry = FileEntry {
            rel: rel.clone(),
            sha256: sha256_hex(&bytes),
            size: bytes.len(),
            class,
            original_scroll: i + 2,
            first_universe: None,
            error: None,
        };
        match class {
            StorageClass::Binary => {
                let err = "stored as binary (bytes are not valid UTF-8/ASCII or contain phext break bytes); not element-parsed".to_string();
                entry.error = Some(err.clone());
                failures.push((rel, err));
            }
            StorageClass::Text => match parse_xml(&bytes) {
                Ok(tree) => {
                    entry.first_universe = Some(next_universe);
                    next_universe += count_universes(&tree);
                }
                Err(e) => {
                    entry.error = Some(e.clone());
                    failures.push((rel, e));
                }
            },
        }
        entries.push(entry);
    }
    // ---- pass 2: write $1, then converted universes in order
    let mut writer = ChainWriter::create(out)?;
    {
        let mut map: HashMap<phext::Coordinate, String> = HashMap::new();
        map.insert(coord(1), build_index_scroll(&entries, &failures));
        for (entry, path) in entries.iter().zip(files.iter()) {
            let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
            let scroll = match entry.class {
                StorageClass::Text => String::from_utf8(bytes).map_err(|e| e.to_string())?,
                StorageClass::Binary => binary::encode_scroll(&bytes),
            };
            map.insert(coord(entry.original_scroll), scroll);
        }
        writer.write_member(&phext::implode(map))?;
    }
    let mut members_written = 1usize;
    for (entry, path) in entries.iter().zip(files.iter()) {
        if entry.error.is_some() {
            continue;
        }
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        let tree = parse_xml(&bytes)?;
        let base = entry.first_universe.unwrap();
        let mut local: Vec<String> = Vec::new();
        let first = emit_file(&tree, &mut local);
        debug_assert_eq!(first, 0);
        for m in &local {
            writer.write_member(&renumber_refs(m, base - 1))?;
            members_written += 1;
        }
    }
    writer.close()?;
    let out_bytes = std::fs::metadata(out).map(|m| m.len()).unwrap_or(0);
    Ok(ConversionSummary { entries, members_written, out_bytes })
}

/// Rewrite every `@ref $k` scroll in a member from local to global
/// numbering by adding `offset` (the file's first-universe number − 1).
/// Goes through libphext explode/implode — no delimiter handling here.
pub fn renumber_refs(member: &str, offset: usize) -> String {
    if offset == 0 {
        return member.to_string();
    }
    let map = phext::explode(member);
    let map: HashMap<phext::Coordinate, String> = map
        .into_iter()
        .map(|(c, s)| {
            let s = if let Some(rest) = s.strip_prefix("@ref $") {
                match rest.trim().parse::<usize>() {
                    Ok(n) => format!("@ref ${}", n + offset),
                    Err(_) => s,
                }
            } else {
                s
            };
            (c, s)
        })
        .collect();
    phext::implode(map)
}

/// Emit a whole file's universes in allocation (pre-order) order.
/// References inside the emitted scrolls are LOCAL (1-based within this
/// file's member list); the caller renumbers them to global $N by adding
/// the file's base. Returns the local index of the root universe (0).
fn emit_file(root: &Element, local: &mut Vec<String>) -> usize {
    emit_local(root, local) - 1
}

fn emit_local(e: &Element, members: &mut Vec<String>) -> usize {
    let slot = members.len();
    members.push(String::new());
    let my = slot + 1; // local universe number, 1-based
    let mut scrolls: Vec<String> = Vec::new();
    push_element_header(&mut scrolls, e);
    for child in &e.children {
        match child {
            Node::Text(t) => scrolls.push(format!("@text\n{}", t)),
            Node::Comment(_) | Node::Pi { .. } => {
                // 0.1's form never represented comments/PIs; the original
                // bytes ride in $1 and stage 0.3 carries them as standoff.
            }
            Node::Elem(c) => {
                if c.is_container() {
                    let child_no = emit_local(c, members);
                    push_element_header(&mut scrolls, c);
                    scrolls.push(format!("@ref ${}", child_no));
                    scrolls.push("@end".to_string());
                } else {
                    push_element_header(&mut scrolls, c);
                    for cc in &c.children {
                        if let Node::Text(t) = cc {
                            scrolls.push(format!("@text\n{}", t));
                        }
                    }
                    scrolls.push("@end".to_string());
                }
            }
        }
    }
    let map: HashMap<phext::Coordinate, String> = scrolls
        .into_iter()
        .enumerate()
        .map(|(i, s)| (coord(i + 1), s))
        .collect();
    members[slot] = phext::implode(map);
    my
}

// ---------------------------------------------------------------------------
// Reader: memory-mapped chain with a coordinate→span index

pub struct ChainReader {
    mmap: memmap2::Mmap,
    members: Vec<(usize, usize)>,
    scrolls: HashMap<(usize, phext::Coordinate), (usize, usize)>,
}

impl ChainReader {
    pub fn open(path: &Path) -> Result<ChainReader, String> {
        let file = std::fs::File::open(path).map_err(|e| format!("open {}: {}", path.display(), e))?;
        let mmap = unsafe { memmap2::Mmap::map(&file) }.map_err(|e| format!("mmap: {}", e))?;
        let text = std::str::from_utf8(&mmap).map_err(|e| format!("chain is not valid UTF-8: {}", e))?;
        // Reference check: libphext must see exactly one closed chain.
        let chains = phext::parse_chains(text);
        if chains.len() != 1 {
            return Err(format!("expected exactly one chain, libphext found {}", chains.len()));
        }
        if !chains[0].closed {
            return Err("chain is not closed (no 0x03)".into());
        }
        // Member spans via a top-level byte scan, cross-checked against
        // libphext's members byte-for-byte; any divergence is fatal.
        let bytes = text.as_bytes();
        if bytes.last() != Some(&phext::CHAIN_CLOSE_U8) {
            return Err("chain close is not the last byte".into());
        }
        let mut spans: Vec<(usize, usize)> = Vec::new();
        let mut start = 0usize;
        for (i, b) in bytes.iter().enumerate() {
            if *b == phext::CHAIN_BREAK_U8 {
                spans.push((start, i));
                start = i + 1;
            }
        }
        spans.push((start, bytes.len() - 1));
        if spans.len() != chains[0].members.len() {
            return Err("chain scan diverges from libphext parse_chains (member count)".into());
        }
        for ((s, e), member) in spans.iter().zip(chains[0].members.iter()) {
            if &text[*s..*e] != member {
                return Err("chain scan diverges from libphext parse_chains (member bytes)".into());
            }
        }
        // Scroll index: one pass per member. libphext's `phokenize` walks
        // the member once and yields (coordinate, scroll) in file order;
        // a byte scan yields the content spans in the same order. Pairing
        // them gives offsets without a rescan per scroll — and every pair
        // is byte-verified against libphext's scroll, so any divergence
        // between the scan and the reference is fatal at open.
        const SCROLL_BREAKS: &[u8] = &[
            0x01, 0x17, 0x18, 0x19, 0x1A, 0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let mut scrolls: HashMap<(usize, phext::Coordinate), (usize, usize)> = HashMap::new();
        for (idx, (s, e)) in spans.iter().enumerate() {
            let member = &text[*s..*e];
            let positioned = phext::phokenize(member);
            // Segments between breaks, in file order. phokenize skips
            // empty coordinate space: its entries pair 1:1, in order, with
            // the NON-EMPTY segments. Empty-scroll entries (sparse space,
            // trailing breaks) get a zero-length span. Every content pair
            // is byte-verified against libphext's scroll.
            let mut member_spans: Vec<(usize, usize)> = Vec::new();
            let mut start = 0usize;
            for (i, b) in member.as_bytes().iter().enumerate() {
                if SCROLL_BREAKS.contains(b) {
                    member_spans.push((start, i));
                    start = i + 1;
                }
            }
            member_spans.push((start, member.len()));
            let content_spans: Vec<(usize, usize)> = member_spans
                .iter()
                .cloned()
                .filter(|(a, b)| b > a)
                .collect();
            let content_entries: Vec<&phext::PositionedScroll> =
                positioned.iter().filter(|p| !p.scroll.is_empty()).collect();
            if content_spans.len() != content_entries.len() {
                return Err(format!(
                    "scroll scan diverges from libphext phokenize in member {} ({} content spans vs {} content scrolls)",
                    idx + 1,
                    content_spans.len(),
                    content_entries.len()
                ));
            }
            for (pos, (a, b)) in content_entries.iter().zip(content_spans.iter()) {
                if &member[*a..*b] != pos.scroll {
                    return Err(format!(
                        "scroll scan diverges from libphext phokenize in member {} at {}",
                        idx + 1,
                        pos.coord.to_string()
                    ));
                }
                scrolls.insert((idx + 1, pos.coord.clone()), (*s + *a, *b - *a));
            }
            for pos in positioned.iter().filter(|p| p.scroll.is_empty()) {
                scrolls.insert((idx + 1, pos.coord.clone()), (*e, 0));
            }
        }
        Ok(ChainReader { mmap, members: spans, scrolls })
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }
    pub fn member(&self, universe: usize) -> Option<&str> {
        let (s, e) = *self.members.get(universe.checked_sub(1)?)?;
        std::str::from_utf8(&self.mmap[s..e]).ok()
    }
    pub fn get(&self, universe: usize, coord: &phext::Coordinate) -> Option<&str> {
        let (s, len) = *self.scrolls.get(&(universe, coord.clone()))?;
        std::str::from_utf8(&self.mmap[s..s + len]).ok()
    }
    /// Scrolls of a universe as (scroll number, content), in scroll order.
    pub fn scrolls_of(&self, universe: usize) -> Vec<(usize, String)> {
        let member = match self.member(universe) {
            Some(m) => m,
            None => return Vec::new(),
        };
        let mut v: Vec<(usize, String)> = phext::explode(member)
            .into_iter()
            .map(|(c, s)| (scroll_number(&c), s))
            .collect();
        v.sort_by_key(|(n, _)| *n);
        v
    }
}

pub fn scroll_number(c: &phext::Coordinate) -> usize {
    c.to_string()
        .rsplit('.')
        .next()
        .and_then(|x| x.parse().ok())
        .unwrap_or(0)
}

/// Parse a `$N:1.1.1/1.1.1/1.1.1` subspace address.
pub fn parse_subspace(addr: &str) -> Result<(usize, phext::Coordinate), String> {
    let rest = addr.strip_prefix('$').ok_or("address must start with $")?;
    let (n, coord) = rest.split_once(':').ok_or("address must be $N:coordinate")?;
    let universe: usize = n.parse().map_err(|_| "bad universe number")?;
    Ok((universe, phext::to_coordinate(coord)))
}

// ---------------------------------------------------------------------------
// $1 index parsing, extract, verify

#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub rel: String,
    pub sha256: String,
    pub size: usize,
    pub class: String,
    pub coord: phext::Coordinate,
    pub universe: Option<usize>,
}

pub fn parse_index(scroll: &str) -> (Vec<IndexEntry>, Vec<(String, String)>) {
    let mut entries = Vec::new();
    let mut failures = Vec::new();
    let mut in_failures = false;
    for line in scroll.lines() {
        if line == "failures:" {
            in_failures = true;
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if in_failures {
            if fields.len() == 2 {
                failures.push((fields[0].to_string(), fields[1].to_string()));
            }
            continue;
        }
        if fields.len() == 6 && (fields[3] == "text" || fields[3] == "binary") {
            entries.push(IndexEntry {
                rel: fields[0].to_string(),
                sha256: fields[1].to_string(),
                size: fields[2].parse().unwrap_or(0),
                class: fields[3].to_string(),
                coord: phext::to_coordinate(fields[4]),
                universe: fields[5].strip_prefix('$').and_then(|n| n.parse().ok()),
            });
        }
    }
    (entries, failures)
}

/// Extract one original back out of $1, verifying its SHA-256.
pub fn extract_original(reader: &ChainReader, rel: &str) -> Result<Vec<u8>, String> {
    let index_scroll = reader
        .get(1, &coord(1))
        .ok_or("no index scroll at $1:1.1.1/1.1.1/1.1.1")?;
    let (entries, _f) = parse_index(index_scroll);
    let entry = entries
        .iter()
        .find(|e| e.rel == rel)
        .ok_or_else(|| format!("no index entry for {}", rel))?;
    if entry.size == 0 {
        // an empty original occupies sparse coordinate space (no text run);
        // its bytes are the empty vec and the sha check below still applies
        let bytes: Vec<u8> = Vec::new();
        if sha256_hex(&bytes) != entry.sha256 {
            return Err(format!("sha256 mismatch extracting {}", rel));
        }
        return Ok(bytes);
    }
    let scroll = reader
        .get(1, &entry.coord)
        .ok_or_else(|| format!("original scroll missing for {}", rel))?;
    let bytes = if entry.class == "binary" {
        binary::decode_scroll(scroll).ok_or("binary scroll does not decode")?
    } else {
        scroll.as_bytes().to_vec()
    };
    if sha256_hex(&bytes) != entry.sha256 {
        return Err(format!("sha256 mismatch extracting {}", rel));
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Decoded views over converted universes (used by verify + tests)

fn scroll_payload(scroll: &str) -> &str {
    match scroll.split_once('\n') {
        Some((_tag, payload)) => payload,
        None => "",
    }
}

fn parse_ref(scroll: &str) -> Option<usize> {
    scroll.strip_prefix("@ref $")?.trim().parse().ok()
}

/// Walk one converted universe subtree: collect (text nodes, refs followed).
/// Mirrors the encoder's grammar exactly.
pub fn universe_text_and_refs(reader: &ChainReader, root_universe: usize) -> (Vec<String>, Vec<usize>) {
    let mut texts = Vec::new();
    let mut refs = Vec::new();
    let mut visited = HashSet::new();
    collect_universe(reader, root_universe, &mut texts, &mut refs, &mut visited);
    (texts, refs)
}

fn collect_universe(
    reader: &ChainReader,
    universe: usize,
    texts: &mut Vec<String>,
    refs: &mut Vec<usize>,
    visited: &mut HashSet<usize>,
) {
    if !visited.insert(universe) {
        return;
    }
    let scrolls = reader.scrolls_of(universe);
    let mut i = 0usize;
    // header: @element, then @attr/@value pairs
    if i < scrolls.len() && scrolls[i].1.starts_with("@element") {
        i += 1;
    }
    while i < scrolls.len() && scrolls[i].1.starts_with("@attr") {
        i += 2; // @attr + @value
    }
    while i < scrolls.len() {
        let s = scrolls[i].1.clone();
        if let Some(_t) = s.strip_prefix("@text") {
            texts.push(scroll_payload(&s).to_string());
            i += 1;
        } else if s.starts_with("@element") {
            i += 1;
            while i < scrolls.len() && scrolls[i].1.starts_with("@attr") {
                i += 2;
            }
            if i < scrolls.len() {
                let inner = scrolls[i].1.clone();
                if let Some(target) = parse_ref(&inner) {
                    refs.push(target);
                    collect_universe(reader, target, texts, refs, visited);
                    i += 1;
                } else {
                    // leaf entry: text nodes until @end
                    while i < scrolls.len() && !scrolls[i].1.starts_with("@end") {
                        let t = scrolls[i].1.clone();
                        if t.starts_with("@text") {
                            texts.push(scroll_payload(&t).to_string());
                        }
                        i += 1;
                    }
                }
            }
            if i < scrolls.len() && scrolls[i].1.starts_with("@end") {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub members: usize,
    pub files: usize,
    pub failures: usize,
    pub originals_verified: usize,
    pub refs_total: usize,
    pub dangling_refs: Vec<usize>,
    pub unreachable_universes: Vec<usize>,
    pub text_mismatches: Vec<String>,
}

pub fn verify(chain: &Path, corpus_dir: Option<&Path>) -> Result<VerifyReport, String> {
    let reader = ChainReader::open(chain)?;
    let mut rep = VerifyReport { members: reader.member_count(), ..Default::default() };
    let index_scroll = reader.get(1, &coord(1)).ok_or("no index scroll")?;
    let (entries, failures) = parse_index(index_scroll);
    rep.files = entries.len();
    rep.failures = failures.len();
    // originals: byte identity for every file
    for e in &entries {
        let bytes = extract_original(&reader, &e.rel)?;
        debug_assert_eq!(sha256_hex(&bytes), e.sha256);
        rep.originals_verified += 1;
    }
    // reference graph: refs from every converted universe
    let converted: HashSet<usize> = entries.iter().filter_map(|e| e.universe).collect();
    let mut edges: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut all_universes: HashSet<usize> = HashSet::new();
    // every universe reachable-from-root set is computed per file below;
    // first gather edges for all members >= 2 that start with @element
    for u in 2..=reader.member_count() {
        let scrolls = reader.scrolls_of(u);
        if let Some(first) = scrolls.first() {
            if first.1.starts_with("@element") {
                all_universes.insert(u);
                // direct refs only: every @ref scroll physically in u is an
                // edge u -> target (refs never nest inside other refs)
                let refs: Vec<usize> = scrolls.iter().filter_map(|(_n, s)| parse_ref(s)).collect();
                for r in &refs {
                    rep.refs_total += 1;
                    if *r < 2 || *r > reader.member_count() {
                        rep.dangling_refs.push(*r);
                    }
                }
                edges.insert(u, refs);
            }
        }
    }
    // reachability from each file root
    let mut reached: HashSet<usize> = HashSet::new();
    let mut stack: Vec<usize> = converted.iter().cloned().collect();
    while let Some(u) = stack.pop() {
        if reached.insert(u) {
            if let Some(rs) = edges.get(&u) {
                stack.extend(rs.iter().cloned());
            }
        }
    }
    let mut unreachable: Vec<usize> = all_universes.difference(&reached).cloned().collect();
    unreachable.sort();
    rep.unreachable_universes = unreachable;
    // text-node sequences vs corpus sources
    if let Some(dir) = corpus_dir {
        for e in &entries {
            if let Some(first) = e.universe {
                let src = std::fs::read(dir.join(&e.rel)).map_err(|err| err.to_string())?;
                let tree = parse_xml(&src)?;
                let mut want: Vec<String> = Vec::new();
                tree.text_nodes(&mut want);
                let (got, _refs) = universe_text_and_refs(&reader, first);
                if got != want {
                    rep.text_mismatches.push(format!(
                        "{}: converted {} text nodes vs source {}",
                        e.rel,
                        got.len(),
                        want.len()
                    ));
                }
            }
        }
    }
    Ok(rep)
}

// ---------------------------------------------------------------------------
// Shared TEI tree helpers (used by the 0.2 Mutable export and 0.3 Phextura;
// moved here from mutable.rs in stage 0.3 so both stages read one copy)

/// First element with this local name in pre-order (self included).
pub fn first_named<'a>(el: &'a Element, name: &str) -> Option<&'a Element> {
    if el.name == name {
        return Some(el);
    }
    for c in &el.children {
        if let Node::Elem(e) = c {
            if let Some(found) = first_named(e, name) {
                return Some(found);
            }
        }
    }
    None
}

/// All text of an element's subtree, concatenated in document order.
pub fn element_text(el: &Element) -> String {
    let mut nodes = Vec::new();
    el.text_nodes(&mut nodes);
    nodes.concat()
}

/// Whitespace-collapse: runs become one space, ends trimmed.
pub fn collapse_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Title: teiHeader/fileDesc/titleStmt/title, fallback msIdentifier/idno,
/// fallback the source filename stem (STAGE2-RECON.md §4.3).
pub fn extract_title(root: &Element, rel: &str) -> String {
    if let Some(header) = first_named(root, "teiHeader") {
        if let Some(stmt) = first_named(header, "titleStmt") {
            if let Some(title) = first_named(stmt, "title") {
                let t = collapse_ws(&element_text(title));
                if !t.is_empty() {
                    return t;
                }
            }
        }
    }
    if let Some(ident) = first_named(root, "msIdentifier") {
        if let Some(idno) = first_named(ident, "idno") {
            let t = collapse_ws(&element_text(idno));
            if !t.is_empty() {
                return t;
            }
        }
    }
    let base = rel.rsplit('/').next().unwrap_or(rel);
    base.rsplit_once('.').map(|(stem, _)| stem.to_string()).unwrap_or_else(|| base.to_string())
}

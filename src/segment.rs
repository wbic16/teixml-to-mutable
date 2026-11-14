//! Shared TEI segmentation (STAGE2-RECON.md §4.4), extracted in stage 0.3
//! so the 0.2 Mutable export and the 0.3 Phextura profile walk one copy of
//! the algorithm and can never drift apart. The normative statement of this
//! table is TEI.md §2 in the phextura repository; a conformance test diffs
//! this compiled-in table against that document.
//!
//! The walk: block-level elements (BLOCK_ELEMENTS) and elements containing
//! a block-level descendant are containers — their direct text forms
//! segments between child blocks. Everything else is inline: its text joins
//! the open segment and the element is recorded as an inline occurrence
//! with half-open Unicode-scalar offsets over the segment text. Consumers
//! derive their own offset conventions from these (0.2's Mutable export
//! uses inclusive Cell offsets: inclusive end = half-open end − 1, and a
//! zero-width occurrence is start == end).
//!
//! Segments are kept raw here (including whitespace-only ones); the
//! keep rule — a segment survives iff its text is non-whitespace or it
//! carries at least one inline occurrence — is applied by consumers, as
//! in 0.2. Comments and PIs encountered during the walk are recorded as
//! marks with their position (ruling D3), never as text.

use crate::{Element, Node};
use std::collections::HashMap;

/// TEI block-level elements: each owns text segments; any other element
/// containing a block-level descendant acts as a container; everything
/// else is inline.
pub const BLOCK_ELEMENTS: &[&str] = &[
    "ab", "additions", "adminInfo", "analytic", "argument", "bibl", "biblStruct",
    "bindingDesc", "body", "back", "cell", "cit", "closer", "custodialHist",
    "decoDesc", "div", "div1", "div2", "div3", "div4", "div5", "div6", "div7",
    "docAuthor", "docDate", "docEdition", "docImprint", "docTitle", "editionStmt",
    "encodingDesc", "epigraph", "facsimile", "fileDesc", "front", "handDesc",
    "head", "history", "imprint", "item", "layoutDesc", "lg", "l", "list",
    "monograph", "msContents", "msDesc", "msItem", "msPart", "notesStmt",
    "objectDesc", "opener", "origin", "additional", "p", "physDesc",
    "profileDesc", "publicationStmt", "quote", "recordHist", "respStmt", "row",
    "series", "seriesStmt", "sealDesc", "sourceDesc", "sp", "stage", "supportDesc",
    "surface", "table", "text", "titlePage", "titlePart", "titleStmt", "zone",
];

pub fn is_block(name: &str) -> bool {
    BLOCK_ELEMENTS.contains(&name)
}

pub fn has_block_descendant(el: &Element) -> bool {
    el.children.iter().any(|c| match c {
        Node::Elem(e) => is_block(&e.name) || has_block_descendant(e),
        _ => false,
    })
}

/// A pre-order flattening of one document tree: occurrence indices,
/// parent/depth, subtree ranges, and per-element descendant text.
pub struct Flat<'a> {
    pub nodes: Vec<&'a Element>,
    pub parent: Vec<Option<usize>>,
    pub depth: Vec<usize>,
    /// Exclusive pre-order bound of each element's subtree.
    pub subtree_end: Vec<usize>,
    /// Descendant text nodes concatenated, per element occurrence.
    pub text: Vec<String>,
    index: HashMap<*const Element, usize>,
}

impl<'a> Flat<'a> {
    pub fn index_of(&self, e: &Element) -> usize {
        self.index[&(e as *const Element)]
    }
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

pub fn flatten(root: &Element) -> Flat<'_> {
    fn go<'a>(
        e: &'a Element,
        parent: Option<usize>,
        depth: usize,
        f: &mut Flat<'a>,
    ) -> usize {
        let idx = f.nodes.len();
        f.nodes.push(e);
        f.parent.push(parent);
        f.depth.push(depth);
        f.subtree_end.push(idx + 1);
        f.text.push(String::new());
        f.index.insert(e as *const Element, idx);
        let mut text = String::new();
        for c in &e.children {
            match c {
                Node::Text(t) => text.push_str(t),
                Node::Elem(ch) => {
                    let ci = go(ch, Some(idx), depth + 1, f);
                    text.push_str(&f.text[ci]);
                }
                Node::Comment(_) | Node::Pi { .. } => {}
            }
        }
        f.subtree_end[idx] = f.nodes.len();
        f.text[idx] = text;
        idx
    }
    let mut f = Flat {
        nodes: Vec::new(),
        parent: Vec::new(),
        depth: Vec::new(),
        subtree_end: Vec::new(),
        text: Vec::new(),
        index: HashMap::new(),
    };
    go(root, None, 0, &mut f);
    f
}

/// One inline element occurrence inside a segment.
#[derive(Debug, Clone, PartialEq)]
pub struct InlineOcc {
    /// Flat (pre-order) index of the element occurrence.
    pub elem: usize,
    pub name: String,
    pub ns: String,
    /// Attributes as written, xmlns declarations excluded (namespace
    /// machinery, not attributes — the namespace rides on `ns`).
    pub attrs: Vec<(String, String)>,
    /// Half-open Unicode-scalar span over the segment's text.
    pub start: usize,
    pub end: usize,
}

/// A comment or PI encountered during the walk (ruling D3).
#[derive(Debug, Clone, PartialEq)]
pub struct SegMark {
    /// Flat index of the element whose children contain the mark.
    pub container: usize,
    /// Ordinal of the mark among that container's marks, in child order.
    pub nth: usize,
    /// Raw segment the mark landed in, when a segment was open.
    pub seg: Option<usize>,
    /// Scalar offset within that segment's text (valid when `seg` is set).
    pub offset: usize,
    /// Last raw segment created before this mark (for stray marks and
    /// marks whose segment is later dropped by the keep rule).
    pub after: Option<usize>,
}

/// One raw segment (pre-keep-rule).
#[derive(Debug, Clone)]
pub struct Segment {
    /// Flat index of the owning element occurrence.
    pub owner: usize,
    pub owner_name: String,
    pub text: String,
    /// Unicode-scalar length of `text`.
    pub scalars: usize,
    pub inlines: Vec<InlineOcc>,
}

#[derive(Debug, Default)]
pub struct Segmentation {
    pub segments: Vec<Segment>,
    pub marks: Vec<SegMark>,
}

struct Walk<'a> {
    flat: &'a Flat<'a>,
    segs: Vec<Segment>,
    marks: Vec<SegMark>,
    last_seg: Option<usize>,
}

impl<'a> Walk<'a> {
    fn seg_for(&mut self, cur: &mut Option<usize>, owner: &Element) -> usize {
        if let Some(i) = *cur {
            return i;
        }
        self.segs.push(Segment {
            owner: self.flat.index_of(owner),
            owner_name: owner.name.clone(),
            text: String::new(),
            scalars: 0,
            inlines: Vec::new(),
        });
        let i = self.segs.len() - 1;
        *cur = Some(i);
        self.last_seg = Some(i);
        i
    }

    fn push_text(&mut self, seg: usize, text: &str) {
        let s = &mut self.segs[seg];
        s.text.push_str(text);
        s.scalars += text.chars().count();
    }

    fn children(&mut self, el: &Element, cur: &mut Option<usize>) {
        let mut nth = 0usize;
        for child in &el.children {
            match child {
                Node::Text(t) => {
                    let i = self.seg_for(cur, el);
                    self.push_text(i, t);
                }
                Node::Elem(e) => {
                    if is_block(&e.name) || has_block_descendant(e) {
                        *cur = None;
                        let mut inner = None;
                        self.children(e, &mut inner);
                    } else {
                        let i = self.seg_for(cur, el);
                        self.inline_into(i, e);
                    }
                }
                Node::Comment(_) | Node::Pi { .. } => {
                    let (seg, offset) = match cur {
                        Some(i) => (Some(*i), self.segs[*i].scalars),
                        None => (None, 0),
                    };
                    self.marks.push(SegMark {
                        container: self.flat.index_of(el),
                        nth,
                        seg,
                        offset,
                        after: self.last_seg,
                    });
                    nth += 1;
                }
            }
        }
    }

    fn inline_into(&mut self, seg: usize, el: &Element) {
        let start = self.segs[seg].scalars;
        let attrs: Vec<(String, String)> = el
            .attrs
            .iter()
            .filter(|(k, _)| k != "xmlns" && !k.starts_with("xmlns:"))
            .cloned()
            .collect();
        let at = self.segs[seg].inlines.len();
        self.segs[seg].inlines.push(InlineOcc {
            elem: self.flat.index_of(el),
            name: el.name.clone(),
            ns: el.ns.clone(),
            attrs,
            start,
            end: start,
        });
        let mut nth = 0usize;
        for child in &el.children {
            match child {
                Node::Text(t) => self.push_text(seg, t),
                Node::Elem(e) => self.inline_into(seg, e),
                Node::Comment(_) | Node::Pi { .. } => {
                    self.marks.push(SegMark {
                        container: self.flat.index_of(el),
                        nth,
                        seg: Some(seg),
                        offset: self.segs[seg].scalars,
                        after: self.last_seg,
                    });
                    nth += 1;
                }
            }
        }
        self.segs[seg].inlines[at].end = self.segs[seg].scalars;
    }
}

/// Segment one document. Identical segmentation to the 0.2 export's
/// Builder (same keep rule inputs, same order); the 0.2 test suite is the
/// regression net.
pub fn segment_document(root: &Element, flat: &Flat) -> Segmentation {
    let mut walk = Walk { flat, segs: Vec::new(), marks: Vec::new(), last_seg: None };
    let mut cur = None;
    walk.children(root, &mut cur);
    Segmentation { segments: walk.segs, marks: walk.marks }
}

/// The keep rule (0.2, recon §4.4): a segment survives iff its text is
/// non-whitespace or it carries at least one inline occurrence.
/// Returns (raw index → kept index) for kept segments.
pub fn kept_map(seg: &Segmentation) -> Vec<Option<usize>> {
    let mut out = Vec::with_capacity(seg.segments.len());
    let mut next = 0usize;
    for s in &seg.segments {
        if !s.text.trim().is_empty() || !s.inlines.is_empty() {
            out.push(Some(next));
            next += 1;
        } else {
            out.push(None);
        }
    }
    out
}

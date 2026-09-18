//! Canonical, collision-free symbol identity (task B-050).
//!
//! Declaration keys are hashed from **length-delimited tuples**, not from string
//! concatenation. `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 7 re-parses
//! a single file and replaces only that owner's edges, so the key of an unchanged
//! symbol must be identical on every run, on every machine and after any restart.
//! Concatenating parts with a separator cannot guarantee that: a symbol named
//! `a::b` and a symbol in namespace `a` called `b` would collapse onto the same
//! key. Prefixing every part with its byte length removes that whole class of
//! collision without needing an escaping rule.
//!
//! ```text
//! canonical_tuple(["a", "b"])  -> "1:a|1:b"
//! canonical_tuple(["a:b"])     -> "3:a:b"
//! ```
//!
//! The digest is FNV-1a over the canonical bytes. It is deliberately not a
//! cryptographic hash: nothing here is a security boundary, and a stable,
//! dependency-free digest keeps the analysis crate buildable with only
//! `graph-core`, `serde` and `serde_json`.

/// Version of the identity scheme.
///
/// Changing the tuple layout or the digest changes every key, so the version is
/// part of the key material and the value is recorded in evidence.
pub const IDENTITY_SCHEME_VERSION: &str = "axiom-identity-1";

/// Separator used between canonical parts, for readability only.
pub const PART_SEPARATOR: char = '|';

/// Encode `parts` as a length-delimited tuple.
///
/// Each part is prefixed with its UTF-8 byte length, so no part can be confused
/// with the boundary of a neighbouring part.
#[must_use]
pub fn canonical_tuple(parts: &[&str]) -> String {
    let mut canonical = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            canonical.push(PART_SEPARATOR);
        }
        canonical.push_str(&part.len().to_string());
        canonical.push(':');
        canonical.push_str(part);
    }
    canonical
}

/// Deterministic hex digest of a canonical tuple.
#[must_use]
pub fn digest(parts: &[&str]) -> String {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in canonical_tuple(parts).as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

/// Stable id of one declaration.
///
/// `kind` is the declaration kind spelling, `path` the semantic nesting
/// (namespace, type, member), and `file` the portably relative source path. The
/// scheme version is hashed first so a scheme change cannot silently map an old
/// key onto a new one.
#[must_use]
pub fn declaration_key(file: &str, kind: &str, path: &[&str]) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(path.len() + 3);
    parts.push(IDENTITY_SCHEME_VERSION);
    parts.push(file);
    parts.push(kind);
    parts.extend_from_slice(path);
    digest(&parts)
}

/// Stable id of a symbol without a known name.
///
/// Anonymous and computed declarations have no name to hash, but they must still
/// be identifiable and stable across runs. The caller passes the syntactic
/// identity it *does* have, such as the declaration kind, the enclosing path and
/// the ordinal inside the file; the result stays deterministic and never
/// pretends to be a name-derived key.
#[must_use]
pub fn anonymous_key(file: &str, kind: &str, ordinal: usize) -> String {
    let ordinal = ordinal.to_string();
    declaration_key(file, kind, &["<anonymous>", &ordinal])
}

#[cfg(test)]
mod tests {
    use super::{anonymous_key, canonical_tuple, declaration_key, digest};

    #[test]
    fn canonical_tuples_are_length_delimited() {
        assert_eq!(canonical_tuple(&["a", "b"]), "1:a|1:b");
        assert_eq!(canonical_tuple(&["a:b"]), "3:a:b");
        assert_ne!(canonical_tuple(&["a", "b"]), canonical_tuple(&["a:b"]));
        assert_ne!(canonical_tuple(&["ab", "c"]), canonical_tuple(&["a", "bc"]));
        assert_eq!(canonical_tuple(&[]), "");
    }

    #[test]
    fn concatenation_collisions_do_not_collide() {
        assert_ne!(digest(&["ab", "c"]), digest(&["a", "bc"]));
        assert_ne!(digest(&["a", "b", "c"]), digest(&["a", "bc"]));
        assert_ne!(digest(&["x"]), digest(&["x", ""]));
    }

    #[test]
    fn unchanged_symbols_keep_their_id_across_repeated_runs() {
        let first = declaration_key("src/app/Foo.cs", "method", &["App", "Foo", "Run"]);
        for _ in 0..5 {
            assert_eq!(
                declaration_key("src/app/Foo.cs", "method", &["App", "Foo", "Run"]),
                first
            );
        }
    }

    #[test]
    fn changing_any_part_changes_the_id() {
        let base = declaration_key("src/app/Foo.cs", "type", &["App", "Foo"]);
        assert_ne!(
            base,
            declaration_key("src/app/Bar.cs", "type", &["App", "Foo"])
        );
        assert_ne!(
            base,
            declaration_key("src/app/Foo.cs", "method", &["App", "Foo"])
        );
        assert_ne!(
            base,
            declaration_key("src/app/Foo.cs", "type", &["App", "Bar"])
        );
    }

    #[test]
    fn anonymous_keys_are_deterministic_and_distinct_by_ordinal() {
        assert_eq!(
            anonymous_key("src/index.ts", "default-export", 0),
            anonymous_key("src/index.ts", "default-export", 0)
        );
        assert_ne!(
            anonymous_key("src/index.ts", "default-export", 0),
            anonymous_key("src/index.ts", "default-export", 1)
        );
    }
}

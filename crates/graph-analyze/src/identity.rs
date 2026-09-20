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
//! A base key is unique for a *semantic* path, but one file may hold two
//! declarations that legitimately share that path: method overloads, a repeated
//! `namespace P { }` block, `partial class Foo` split across two blocks and
//! constructor overloads. The graph data contract rejects a file whose fact set
//! repeats a node or edge id, so [`unique_declaration_keys`] rewrites every key
//! that repeats *inside one file*, and only those, with an occurrence ordinal
//! ([`repeated_declaration_key`]). A file with no repeated key keeps every key
//! exactly as [`declaration_key`] produced it.
//!
//! The digest is FNV-1a over the canonical bytes. It is deliberately not a
//! cryptographic hash: nothing here is a security boundary, and a stable,
//! dependency-free digest keeps the analysis crate buildable with only
//! `graph-core`, `serde` and `serde_json`.

use std::collections::HashMap;

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

/// Marker part that stands in the declaration-kind slot of a repeated-key
/// identity.
///
/// It is hashed as its own length-delimited part, and it is never a
/// `CsharpDeclarationKind` or TypeScript kind spelling, so no key produced by
/// [`repeated_declaration_key`] can equal a key produced by
/// [`declaration_key`]: the two tuples would have to agree on the kind slot,
/// and `#occurrence` is not a declaration kind.
pub const OCCURRENCE_MARKER: &str = "#occurrence";

/// Stable id of the `occurrence`-th declaration that repeats a base key inside
/// one file.
///
/// `base_key` is the [`declaration_key`] the declaration would have had if it
/// were the only declaration on its semantic path. The occurrence ordinal is
/// the declaration's position in source order within the repeated group, which
/// depends only on the bytes of the one file being analysed, so the result is
/// deterministic across runs, machines and restarts for an unchanged file.
#[must_use]
pub fn repeated_declaration_key(base_key: &str, occurrence: usize) -> String {
    let occurrence = occurrence.to_string();
    digest(&[
        IDENTITY_SCHEME_VERSION,
        base_key,
        OCCURRENCE_MARKER,
        &occurrence,
    ])
}

/// Make one file's declaration keys unique, in source order.
///
/// `base_keys` are the keys [`declaration_key`] produced for every declaration
/// of a *single* file, in source order. A key that occurs once in the file is
/// returned unchanged, byte for byte, so a file with no repeated key keeps
/// exactly the keys it had before this function existed. Only a key that
/// repeats inside that file is replaced, everywhere it occurs, by
/// [`repeated_declaration_key`] keyed on its occurrence ordinal in source
/// order; every member of the group is rewritten so the rule is symmetric and
/// no member keeps an ambiguous key.
///
/// The function sees one file's keys and nothing else, which is what the
/// reconciliation protocol needs: re-parsing one changed file replaces only
/// that file's facts, so keys in every other file must not depend on it.
#[must_use]
pub fn unique_declaration_keys(base_keys: &[String]) -> Vec<String> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for key in base_keys {
        *counts.entry(key.as_str()).or_insert(0) += 1;
    }
    let mut seen: HashMap<&str, usize> = HashMap::new();
    let mut unique = Vec::with_capacity(base_keys.len());
    for key in base_keys {
        if counts.get(key.as_str()).copied().unwrap_or(0) > 1 {
            let occurrence = seen.entry(key.as_str()).or_insert(0);
            unique.push(repeated_declaration_key(key, *occurrence));
            *occurrence += 1;
        } else {
            unique.push(key.clone());
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::{
        anonymous_key, canonical_tuple, declaration_key, digest, repeated_declaration_key,
        unique_declaration_keys,
    };

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

    #[test]
    fn unique_declaration_keys_leave_a_collision_free_file_untouched() {
        let base = vec![
            declaration_key("src/app/Core.cs", "namespace", &["App.Core"]),
            declaration_key("src/app/Core.cs", "class", &["App.Core", "Thing"]),
            declaration_key("src/app/Core.cs", "method", &["App.Core", "Thing", "Run"]),
        ];
        assert_eq!(unique_declaration_keys(&base), base);
    }

    #[test]
    fn unique_declaration_keys_disambiguate_every_member_of_a_repeated_group() {
        let repeated = declaration_key("src/app/Core.cs", "method", &["App.Core", "Thing", "Get"]);
        let keys = vec![
            declaration_key("src/app/Core.cs", "class", &["App.Core", "Thing"]),
            repeated.clone(),
            repeated.clone(),
            declaration_key("src/app/Core.cs", "method", &["App.Core", "Thing", "Run"]),
        ];
        let unique = unique_declaration_keys(&keys);

        assert_eq!(unique[0], keys[0], "the unique class key is unchanged");
        assert_eq!(unique[3], keys[3], "the unique method key is unchanged");
        assert_eq!(unique[1], repeated_declaration_key(&repeated, 0));
        assert_eq!(unique[2], repeated_declaration_key(&repeated, 1));
        assert_ne!(unique[0], unique[1]);
        assert_ne!(unique[1], unique[2]);
        assert_ne!(
            unique[1], unique[0],
            "no rewritten key may fall back onto another declaration's key"
        );
    }

    #[test]
    fn unique_declaration_keys_are_stable_across_repeated_calls() {
        let repeated = declaration_key("src/app/Core.cs", "method", &["App.Core", "Thing", "Get"]);
        let keys = vec![repeated.clone(), repeated.clone(), repeated.clone()];
        let first = unique_declaration_keys(&keys);
        for _ in 0..5 {
            assert_eq!(unique_declaration_keys(&keys), first);
        }
        assert_eq!(first.len(), 3);
        assert!(first[0] != first[1] && first[1] != first[2] && first[0] != first[2]);
    }

    #[test]
    fn occurrence_ordinals_follow_source_order_and_are_file_local() {
        let a = declaration_key("src/app/Core.cs", "method", &["App.Core", "Thing", "Get"]);
        let b = declaration_key("src/other/Core.cs", "method", &["App.Core", "Thing", "Get"]);
        let first_file = unique_declaration_keys(&[a.clone(), a.clone()]);
        let second_file = unique_declaration_keys(&[b.clone(), b.clone()]);
        assert_eq!(first_file[0], repeated_declaration_key(&a, 0));
        assert_eq!(second_file[0], repeated_declaration_key(&b, 0));
        assert_ne!(
            first_file[0], second_file[0],
            "the same semantic path in another file keeps a distinct key"
        );
    }

    #[test]
    fn a_repeated_key_never_collides_with_a_base_key() {
        // `declaration_key` hashes the declaration kind in the slot that
        // `repeated_declaration_key` fills with `#occurrence`, and `#occurrence`
        // is never a declaration kind, so the two families cannot meet.
        let base = declaration_key("src/app/Core.cs", "method", &["App.Core", "Thing", "Get"]);
        for occurrence in 0..16 {
            let repeated = repeated_declaration_key(&base, occurrence);
            assert_ne!(repeated, base);
            assert_ne!(
                repeated,
                declaration_key("src/app/Core.cs", "method", &["App.Core", "Thing", "Get"])
            );
        }
    }
}

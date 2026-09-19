//! V2-013 - portable path-key validation: positive, negative and boundary legs.
//!
//! Every leg runs the real policy: the portability rule is `graph-core`'s
//! `validate_portable_relative_path`, the detection keys are this crate's
//! generated Unicode NFD tables. Nothing here is a stand-in for the code under
//! test, and no leg rewrites a spelling.

use std::str::FromStr;

use axiom_platform::collisions::{
    detect_portable_collisions, Collision, CollisionKind, DetectError,
};
use axiom_platform::path_key::{PathKey, PathKeyError, ERR_UNSAFE_PORTABLE_PATH};
use axiom_platform::unicode::{canonical_combining_class, nfd, UNICODE_DATA_VERSION};

/// `cafe\u{e9}.ts` precomposed - `café.ts`.
const CAFE_NFC: &str = "caf\u{e9}.ts";
/// The same name with a combining acute - `cafe\u{301}.ts`.
const CAFE_NFD: &str = "cafe\u{301}.ts";
/// `espa\u{f1}a.ts` precomposed - `españa.ts`.
const ESPANA_NFC: &str = "espa\u{f1}a.ts";
/// The same name decomposed - `espan\u{303}a.ts`.
const ESPANA_NFD: &str = "espan\u{303}a.ts";
/// LATIN CAPITAL LETTER I WITH DOT ABOVE.
const I_DOT: &str = "\u{130}.ts";
/// `i` + COMBINING DOT ABOVE, the case-folded spelling of [`I_DOT`].
const I_PLUS_DOT: &str = "i\u{307}.ts";

fn refused(spelling: &str) -> PathKeyError {
    match PathKey::new(spelling) {
        Ok(key) => panic!("expected a refusal for {spelling:?}, got {key:?}"),
        Err(error) => error,
    }
}

fn collision_of(legs: [&str; 2]) -> Collision {
    match detect_portable_collisions(legs) {
        Ok(keys) => panic!("expected a collision, got {keys:?}"),
        Err(DetectError::Collision(found)) => found,
        Err(other) => panic!("expected a collision, got {other}"),
    }
}

// ---------------------------------------------------------------- Unicode NFD

#[test]
fn unicode_tables_report_the_version_they_were_generated_from() {
    assert_eq!(UNICODE_DATA_VERSION, "15.1.0");
}

#[test]
fn combining_class_matches_the_unicode_database() {
    assert_eq!(canonical_combining_class('\u{301}'), 230);
    assert_eq!(canonical_combining_class('\u{328}'), 202);
    assert_eq!(canonical_combining_class('a'), 0);
    assert_eq!(canonical_combining_class('\u{1100}'), 0);
}

#[test]
fn nfd_decomposes_precomposed_latin_and_is_idempotent() {
    assert_eq!(nfd(CAFE_NFC), CAFE_NFD);
    assert_eq!(nfd(CAFE_NFD), CAFE_NFD);
    assert_eq!(nfd(ESPANA_NFC), ESPANA_NFD);
    assert_eq!(nfd(ESPANA_NFD), ESPANA_NFD);
    assert_eq!(nfd(I_DOT), "I\u{307}.ts");
}

#[test]
fn nfd_decomposes_hangul_syllables_algorithmically() {
    // Not tabulated by the generator: the Hangul algorithm covers the whole
    // precomposed syllable block.
    assert_eq!(nfd("\u{ac01}"), "\u{1100}\u{1161}\u{11a8}");
    assert_eq!(nfd("\u{ac00}"), "\u{1100}\u{1161}");
}

#[test]
fn nfd_applies_canonical_ordering_by_combining_class() {
    // U+0301 (class 230) and U+0328 (class 202) must sort by class, not by
    // their order of appearance.
    assert_eq!(nfd("a\u{301}\u{328}"), "a\u{328}\u{301}");
    assert_eq!(nfd("a\u{328}\u{301}"), "a\u{328}\u{301}");
}

// ------------------------------------------------------- path identity (CP-03)

#[test]
fn accepts_portable_spellings_and_preserves_them_byte_for_byte() {
    let precomposed = PathKey::new(CAFE_NFC).expect("precomposed spelling is portable");
    let decomposed = PathKey::from_str(CAFE_NFD).expect("decomposed spelling is portable");
    assert_eq!(precomposed.as_str(), CAFE_NFC);
    assert_eq!(decomposed.as_str(), CAFE_NFD);
    assert_ne!(precomposed.as_str(), decomposed.as_str());
    assert_eq!(precomposed.clone().into_string(), CAFE_NFC);

    // A non-ASCII, non-Latin name is preserved exactly (Thai: `ai fai`).
    let thai = PathKey::new("\u{e44}\u{e1f}.ts").expect("Thai file name is portable");
    assert_eq!(thai.as_str(), "\u{e44}\u{e1f}.ts");

    // Interior dots and dashes are ordinary characters.
    let nested = PathKey::new("src/a-b.c/graph.v2.ts").expect("nested portable path");
    assert_eq!(nested.as_str(), "src/a-b.c/graph.v2.ts");
}

#[test]
fn refuses_every_unsafe_portable_spelling_and_keeps_the_observed_bytes() {
    let cases: &[&str] = &[
        "",
        "../escape.ts",
        "a/../b.ts",
        "./here.ts",
        "a//b.ts",
        "/abs.ts",
        "C:/drive.ts",
        "C:drive.ts",
        r"\\?\C:\device.ts",
        r"a\b.ts",
        "nested/../up.ts",
        "CON.ts",
        "com1.txt",
        "aux",
        "trailing.ts.",
        "trailing .ts ",
        "ads.ts:stream",
        "nul\u{0}.ts",
    ];
    for spelling in cases {
        let error = refused(spelling);
        assert_eq!(error.code(), ERR_UNSAFE_PORTABLE_PATH, "case {spelling:?}");
        // The refused bytes are reported unchanged, never normalised.
        assert_eq!(error.path(), *spelling, "case {spelling:?}");
        assert!(!error.reason().is_empty(), "case {spelling:?}");
        assert!(
            error.to_string().contains(ERR_UNSAFE_PORTABLE_PATH),
            "case {spelling:?}"
        );
    }
}

#[test]
fn byte_budget_boundary_is_checked_per_segment_and_for_the_whole_path() {
    // 255 bytes in one segment is the documented maximum and is accepted.
    let at_segment_limit = "a".repeat(255);
    assert!(PathKey::new(&at_segment_limit).is_ok());

    // 256 bytes in one segment is refused, and the refusal names the spelling.
    let over_segment_limit = "a".repeat(256);
    assert_eq!(refused(&over_segment_limit).path(), over_segment_limit);

    // The largest path that maximal legal segments can build is accepted.
    let sixteen = vec!["a".repeat(255); 16].join("/");
    assert_eq!(sixteen.len(), 4095);
    assert!(PathKey::new(&sixteen).is_ok());

    // One more full segment crosses the 4096-byte whole-path budget.
    let seventeen = vec!["a".repeat(255); 17].join("/");
    assert_eq!(seventeen.len(), 4351);
    let error = refused(&seventeen);
    assert_eq!(error.path(), seventeen);
}

// ------------------------------------------------- derived detection keys

#[test]
fn detection_keys_are_derived_on_demand_and_never_stored_in_place() {
    let key = PathKey::new(CAFE_NFC).expect("portable");
    assert_eq!(key.casefold_key(), CAFE_NFC);
    assert_eq!(key.normalization_key(), CAFE_NFD);
    assert_eq!(key.collision_key(), CAFE_NFD);
    // The identity itself is untouched by those derivations.
    assert_eq!(key.as_str(), CAFE_NFC);
    assert!(!key.is_in_nfd());
    assert!(PathKey::new(CAFE_NFD).expect("portable").is_in_nfd());
}

#[test]
fn collision_detector_accepts_a_set_of_distinct_portable_paths_in_order() {
    let keys = detect_portable_collisions(["a.ts", "b.ts", "c/d.ts"]).expect("no collision");
    let spellings: Vec<&str> = keys.iter().map(PathKey::as_str).collect();
    assert_eq!(spellings, vec!["a.ts", "b.ts", "c/d.ts"]);
}

#[test]
fn duplicate_spelling_is_reported_as_a_defect_not_silently_deduplicated() {
    let found = collision_of(["src/a.ts", "src/a.ts"]);
    assert_eq!(found.kind(), CollisionKind::Duplicate);
    assert_eq!(found.rule(), "duplicate-identity");
    assert!(!found.case_difference());
    assert!(!found.normalization_difference());
    assert_eq!(found.first(), "src/a.ts");
    assert_eq!(found.second(), "src/a.ts");
}

#[test]
fn case_only_collision_is_classified_as_case() {
    let found = collision_of(["src/A.ts", "src/a.ts"]);
    assert_eq!(found.kind(), CollisionKind::CaseOnly);
    assert_eq!(found.rule(), "case-only-collision");
    assert!(found.case_difference());
    assert!(!found.normalization_difference());
    assert_eq!(found.first(), "src/A.ts");
    assert_eq!(found.second(), "src/a.ts");
}

#[test]
fn canonical_equivalence_without_case_is_classified_as_normalization() {
    // No letter case takes part here at all: only NFC vs NFD.
    let found = collision_of([ESPANA_NFC, ESPANA_NFD]);
    assert_eq!(found.kind(), CollisionKind::Normalization);
    assert_eq!(found.rule(), "normalization-collision");
    assert!(!found.case_difference());
    assert!(found.normalization_difference());
    assert_eq!(found.first(), ESPANA_NFC);
    assert_eq!(found.second(), ESPANA_NFD);
}

#[test]
fn nfd_spelling_of_cafe_collides_with_the_precomposed_spelling() {
    let found = collision_of([CAFE_NFC, CAFE_NFD]);
    assert_eq!(found.kind(), CollisionKind::Normalization);
    assert!(!found.case_difference());
    assert!(found.normalization_difference());
}

#[test]
fn casefold_equivalence_across_normalization_forms_is_case_only() {
    // `\u{130}` lowercases to `i\u{307}`, so the two spellings collide purely
    // through case folding.
    let found = collision_of([I_DOT, I_PLUS_DOT]);
    assert_eq!(found.kind(), CollisionKind::CaseOnly);
    assert!(found.case_difference());
    assert!(!found.normalization_difference());
}

#[test]
fn distinct_spellings_that_only_look_alike_are_accepted() {
    // Different base letters: no collision despite the shared diacritic.
    let keys = detect_portable_collisions(["a\u{301}.ts", "e\u{301}.ts"]).expect("no collision");
    assert_eq!(keys.len(), 2);
}

#[test]
fn an_unsafe_spelling_in_a_set_is_reported_as_invalid_not_as_a_collision() {
    match detect_portable_collisions(["ok.ts", "../escape.ts"]) {
        Err(DetectError::Invalid(error)) => {
            assert_eq!(error.code(), ERR_UNSAFE_PORTABLE_PATH);
            assert_eq!(error.path(), "../escape.ts");
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
    let error = detect_portable_collisions(["ok.ts", "../escape.ts"]).expect_err("refused");
    assert_eq!(error.code(), ERR_UNSAFE_PORTABLE_PATH);
    assert!(error.to_string().contains("../escape.ts"));
}

#[test]
fn refusals_map_onto_the_shared_typed_error_without_losing_the_spelling() {
    let details = refused("/abs.ts").to_axiom_error();
    assert_eq!(
        details.details().get("portable_path").map(String::as_str),
        Some("/abs.ts")
    );

    let collision = collision_of(["src/A.ts", "src/a.ts"]).to_axiom_error();
    assert_eq!(
        collision.details().get("rule").map(String::as_str),
        Some("case-only-collision")
    );
    assert_eq!(
        collision.details().get("observed").map(String::as_str),
        Some("src/A.ts")
    );
    assert_eq!(
        collision.details().get("portable_path").map(String::as_str),
        Some("src/a.ts")
    );
}

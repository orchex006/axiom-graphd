//! Canonical decomposition (Unicode NFD) for portable path identity (V2-013).
//!
//! `graph-core::paths::detect_case_collisions` detects case hazards only and
//! documents that canonical-equivalence detection "requires a normalisation
//! table and belongs to the identifier/portability tasks". This module is that
//! table plus the algorithm, and nothing here rewrites a source path: the
//! normalised spelling is a *detection key*, never a stored identity.
//!
//! The data comes from [`crate::unicode_tables`], generated from the Unicode
//! character database by `tools/gen_unicode_tables.py`. Hangul syllables are
//! algorithmic (Unicode 3.12) and therefore derived here rather than tabulated,
//! so the normalizer is complete for the recorded Unicode version instead of a
//! silent subset.

use crate::unicode_tables::{
    CANONICAL_COMBINING_CLASSES, CANONICAL_DECOMPOSITIONS, UNICODE_VERSION,
};

/// Unicode version of the generated tables.
pub const UNICODE_DATA_VERSION: &str = UNICODE_VERSION;

/// Hangul syllable composition constants (Unicode 3.12, section 3.12).
const HANGUL_S_BASE: u32 = 0xAC00;
const HANGUL_L_BASE: u32 = 0x1100;
const HANGUL_V_BASE: u32 = 0x1161;
const HANGUL_T_BASE: u32 = 0x11A7;
const HANGUL_L_COUNT: u32 = 19;
const HANGUL_V_COUNT: u32 = 21;
const HANGUL_T_COUNT: u32 = 28;
const HANGUL_N_COUNT: u32 = HANGUL_V_COUNT * HANGUL_T_COUNT;
const HANGUL_S_COUNT: u32 = HANGUL_L_COUNT * HANGUL_N_COUNT;

/// Canonical combining class of `character`, or 0 when it is a starter.
#[must_use]
pub fn canonical_combining_class(character: char) -> u8 {
    let classes: &[(u32, u8)] = CANONICAL_COMBINING_CLASSES;
    match classes.binary_search_by_key(&(character as u32), |&(key, _)| key) {
        Ok(index) => classes[index].1,
        Err(_) => 0,
    }
}

fn canonical_decomposition(character: char) -> Option<&'static str> {
    let decompositions: &[(u32, &str)] = CANONICAL_DECOMPOSITIONS;
    match decompositions.binary_search_by_key(&(character as u32), |&(key, _)| key) {
        Ok(index) => Some(decompositions[index].1),
        Err(_) => None,
    }
}

fn jamo(codepoint: u32) -> char {
    // Every value built from the HANGUL constants below is a valid scalar value,
    // so the fallback is unreachable; keeping it avoids a panic path in a library.
    char::from_u32(codepoint).unwrap_or(char::REPLACEMENT_CHARACTER)
}

fn decompose_into(character: char, out: &mut Vec<char>) {
    let codepoint = character as u32;
    if (HANGUL_S_BASE..HANGUL_S_BASE + HANGUL_S_COUNT).contains(&codepoint) {
        let syllable = codepoint - HANGUL_S_BASE;
        let lead = HANGUL_L_BASE + syllable / HANGUL_N_COUNT;
        let vowel = HANGUL_V_BASE + (syllable % HANGUL_N_COUNT) / HANGUL_T_COUNT;
        let trail = HANGUL_T_BASE + syllable % HANGUL_T_COUNT;
        out.push(jamo(lead));
        out.push(jamo(vowel));
        if trail != HANGUL_T_BASE {
            out.push(jamo(trail));
        }
        return;
    }
    match canonical_decomposition(character) {
        // The generator asserts every tabulated expansion is already fully
        // decomposed, so one lookup replaces the recursive walk.
        Some(expansion) => out.extend(expansion.chars()),
        None => out.push(character),
    }
}

/// Canonical ordering: stable insertion sort of each non-starter run by class.
fn canonical_order(characters: &mut [char]) {
    for index in 1..characters.len() {
        let class = canonical_combining_class(characters[index]);
        if class == 0 {
            continue;
        }
        let mut position = index;
        while position > 0 {
            let previous = canonical_combining_class(characters[position - 1]);
            if previous == 0 || previous <= class {
                break;
            }
            characters.swap(position - 1, position);
            position -= 1;
        }
    }
}

/// Canonical form D (NFD) of `text`.
///
/// This is a pure function: it never touches the filesystem and never mutates
/// its input. Callers use the result as a comparison key only.
#[must_use]
pub fn nfd(text: &str) -> String {
    let mut characters = Vec::with_capacity(text.len());
    for character in text.chars() {
        decompose_into(character, &mut characters);
    }
    canonical_order(&mut characters);
    characters.into_iter().collect()
}

/// True when `text` is already in canonical form D.
#[must_use]
pub fn is_nfd(text: &str) -> bool {
    nfd(text) == text
}

/// True when `text` has at least one character with a canonical decomposition.
#[must_use]
pub fn has_canonical_decomposition(text: &str) -> bool {
    text.chars()
        .any(|character| canonical_decomposition(character).is_some())
}

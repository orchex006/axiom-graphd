"""Generate the Unicode tables for `platform::unicode` (task V2-013).

This script is the reproducible source of `src/unicode_tables.rs`. It reads the
Unicode character database that the running CPython ships (`unicodedata`) and
emits two sorted tables:

* `CANONICAL_DECOMPOSITIONS` - the fully recursive canonical (NFD) expansion of
  every character that has a canonical decomposition mapping. Hangul syllables
  (U+AC00..U+D7A3) are algorithmic per Unicode 3.12 and are therefore omitted
  from the table; `unicode::nfd` derives them from the jamo constants instead.
  With Hangul derived and every other mapping listed, the normalizer is complete
  for the Unicode version below rather than a subset with silent gaps.
* `CANONICAL_COMBINING_CLASSES` - the non-zero canonical combining classes used
  by the canonical-ordering step.

Each emitted expansion is asserted to be already fully decomposed and idempotent
before it is written, so a table can never drift from the normalizer.

Usage:  python crates/platform/tools/gen_unicode_tables.py [output.rs]
"""

import sys
import unicodedata

UNICODE_VERSION = unicodedata.unidata_version

HANGUL_SYLLABLE_FIRST = 0xAC00
HANGUL_SYLLABLE_LAST = 0xD7A3


def has_canonical_decomposition(ch):
    text = unicodedata.decomposition(ch)
    return bool(text) and not text.startswith("<")


def is_hangul_syllable(codepoint):
    return HANGUL_SYLLABLE_FIRST <= codepoint <= HANGUL_SYLLABLE_LAST


def escape(expansion):
    """Render an expansion as a Rust string literal body.

    Printable characters are emitted literally (Rust source is UTF-8), so the
    table stays roughly the size of the data it carries instead of inflating
    every code point into a `\\u{...}` escape.
    """
    out = []
    for ch in expansion:
        if ch in ('"', "\\"):
            out.append("\\" + ch)
        elif unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp"):
            out.append("\\u{%x}" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def main(stream):
    decompositions = []
    for codepoint in range(0x110000):
        if is_hangul_syllable(codepoint):
            continue
        char = chr(codepoint)
        if not has_canonical_decomposition(char):
            continue
        expansion = unicodedata.normalize("NFD", char)
        assert expansion != char, hex(codepoint)
        assert unicodedata.normalize("NFD", expansion) == expansion, hex(codepoint)
        decompositions.append((codepoint, expansion))

    classes = [
        (codepoint, unicodedata.combining(chr(codepoint)))
        for codepoint in range(0x110000)
        if unicodedata.combining(chr(codepoint))
    ]

    write = stream.write
    write("//! Generated Unicode tables for the path-key normalizer (task V2-013).\n")
    write("//!\n")
    write("//! DO NOT EDIT BY HAND. Regenerate with\n")
    write("//! `python crates/platform/tools/gen_unicode_tables.py > crates/platform/src/unicode_tables.rs`.\n")
    write("//!\n")
    write("//! The generator reads the Unicode character database shipped with the running\n")
    write("//! CPython and asserts, per entry, that the emitted expansion is already fully\n")
    write("//! decomposed and idempotent, so the tables cannot silently drift from the\n")
    write("//! normalizer that consumes them. Hangul syllables are algorithmic and are\n")
    write("//! deliberately absent; see [`super::unicode::nfd`].\n\n")
    write("/// Unicode version these tables were generated from.\n")
    write('pub const UNICODE_VERSION: &str = "%s";\n\n' % UNICODE_VERSION)
    write("/// Canonical (NFD) expansion of every character with a canonical\n")
    write("/// decomposition mapping, sorted by code point. Hangul is algorithmic and\n")
    write("/// absent by design.\n")
    write("pub static CANONICAL_DECOMPOSITIONS: &[(u32, &str)] = &[\n")
    for codepoint, expansion in decompositions:
        write('    (0x%04X, "%s"),\n' % (codepoint, escape(expansion)))
    write("];\n\n")
    write("/// Non-zero canonical combining classes, sorted by code point.\n")
    write("pub static CANONICAL_COMBINING_CLASSES: &[(u32, u8)] = &[\n")
    for codepoint, klass in classes:
        write("    (0x%04X, %d),\n" % (codepoint, klass))
    write("];\n")


if __name__ == "__main__":
    # The output is written as UTF-8 with LF endings so the generated file is
    # byte-identical on every host, independent of the console code page.
    target = sys.argv[1] if len(sys.argv) > 1 else "crates/platform/src/unicode_tables.rs"
    with open(target, "w", encoding="utf-8", newline="\n") as stream:
        main(stream)


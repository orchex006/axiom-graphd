//! TypeScript declaration extraction (task B-049).
//!
//! Like the C# scanner this is a narrow line scan, not a full TypeScript parser.
//! Its distinguishing requirement is honesty about identity: a class, function or
//! exported member gets a key derived from its explicit name, while an
//! anonymous declaration (for example `export default function () {}`) and a
//! computed or destructured name are marked with an explicit
//! [`IdentityQuality`] instead of being given a fabricated name. A caller can
//! therefore tell "this symbol is called `run`" apart from "this symbol has no
//! name we can key on yet", which a plain `Option<String>` would hide.

pub mod declarations;

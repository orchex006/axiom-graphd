//! C# declaration extraction (task B-048).
//!
//! The extractor is a deliberate, narrow line scan rather than a full C# parser.
//! It recognises the declaration forms the reconciliation work package needs -
//! namespaces, types, interfaces and methods - and it records the exact byte span
//! of every name, because `graph-store` replaces one owner's edges using those
//! spans and a wrong span silently attributes a fact to the wrong symbol.
//!
//! Anything the scanner does not recognise is reported through
//! [`CsharpAnalysis::diagnostics`]. Malformed input such as `class {` or an
//! unbalanced brace never panics and never yields a clean, complete result; it
//! yields a diagnostic, and a caller that respects coverage must lower its claim.

pub mod declarations;

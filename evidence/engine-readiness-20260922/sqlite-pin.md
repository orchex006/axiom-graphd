# Local SQLite pin evidence

This local evidence records the bounded V2-021 runtime repair. It is not a
release or certification claim.

The former locked pair was `rusqlite 0.37.0` and `libsqlite3-sys 0.35.0`;
the native default-WAL smoke observed SQLite `3.50.2`, below the existing
`3.51.3` contract. A direct `libsqlite3-sys` update was refused by Cargo
because `rusqlite 0.37.0` requires `^0.35.0`.

The minimum compatible bundled pair is `rusqlite 0.39.0` and
`libsqlite3-sys 0.37.0`. The bundled source header declares
`SQLITE_VERSION "3.51.3"` in
`libsqlite3-sys-0.37.0/sqlite3/sqlite3.h`.

The lockfile resolver delta is limited to the new pair and its required
transitives: `foldhash`, `hashbrown`, `hashlink`, `bumpalo`, `js-sys`,
`rsqlite-vfs`, `rustversion`, `sqlite-wasm-rs`, `thiserror`,
`thiserror-impl`, and the `wasm-bindgen` family. No application dependency
or SQLite minimum/default policy changed.

# Persistent foreground runtime regression

Executed from the primary checkout on 2026-09-22:

```text
$ cargo check -p axiom-graphd
Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.25s

$ cargo test -p axiom-graphd --lib
test result: ok. 149 passed; 0 failed

$ cargo test -p axiom-graphd catalog_runtime --lib
test result: ok. 3 passed; 0 failed

$ cargo test -p axiom-graphd commands::solution --lib
test result: ok. 5 passed; 0 failed

$ sh evidence/local-lifecycle-20260922/run-persistent-regression.sh
persistent_generation=cca002b56cc28518d492e4574ebf54141a13770e09131a86dc651aa29d8633cf
updated_generation=7a081ebefd5679f6e3929bc9a1601bff05cc71bba22e950f7716299b3acb146c
lock_reacquired=true
```

The subprocess fixture registers an explicitly selected `catalog_host_repo`,
starts `serve`, waits for its first immutable catalog pointer, edits C# source,
observes a different catalog generation without restarting, sends SIGINT and
then runs a fresh `reconcile` process. The successful reconcile proves the
foreground daemon released its instance lock after bounded drain.

//! The shipped migration argv must execute, rather than answer a stub refusal.
use std::process::Command;

#[test]
fn fresh_repository_has_a_real_read_only_migration_plan() {
    let root = tempfile::tempdir().expect("isolated repository");
    let output = Command::new(env!("CARGO_BIN_EXE_axiom"))
        .current_dir(root.path())
        .env("AXIOM_HOME", root.path().join("home"))
        .args(["migrate", "plan", "--solution", "sample", "--json"])
        .output()
        .expect("launch actual CLI");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).expect("one JSON plan");
    assert_eq!(plan["status"], "ready");
    assert_eq!(plan["migration_needed"], false);
    assert!(!root.path().join(".axiom").exists());
    assert!(!root.path().join(".agrimap-agent").exists());
}

#!/usr/bin/env python3
"""One scoped macOS lifecycle: distribution install, LaunchAgent, catalog and MCP.

This creates only a temporary AXIOM_HOME and HOME.  It never starts graphd in
the foreground: catalog changes must be produced by the installed LaunchAgent.
"""
from __future__ import annotations
import importlib.util, hashlib, json, os, shutil, subprocess, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
GRAPHD, CLI, MCP = HERE.parents[1], HERE.parents[1].parent / "axiom-cli", HERE.parents[1].parent / "axiom-mcp"
spec = importlib.util.spec_from_file_location("mcp_e2e", HERE / "run-mcp-catalog-e2e.py")
assert spec and spec.loader
mcp = importlib.util.module_from_spec(spec); spec.loader.exec_module(mcp)
PYTHON = MCP / ".venv/bin/python"
LABEL = "com.axiom.axiom-graphd"

def run(argv, env, *, expected=0):
    result = subprocess.run(argv, env=env, text=True, capture_output=True)
    if result.returncode != expected:
        raise RuntimeError(f"{argv}: {result.returncode}: {result.stdout} {result.stderr}")
    return result

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def wait_catalog(pointer, prior=None):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if pointer.is_file():
            value = mcp.catalog_id(pointer)
            if value != prior: return value
        time.sleep(.25)
    raise TimeoutError("LaunchAgent did not publish the expected catalog")

def query_wheel(wheel, home, repo, needle, env):
    code = "import sys,json,importlib.util;sys.path.insert(0,sys.argv[1]);import axiom_mcp;assert axiom_mcp.__file__.startswith(sys.argv[1]);s=importlib.util.spec_from_file_location('h',sys.argv[2]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(json.dumps({'origin':axiom_mcp.__file__,'query':m.query(__import__('pathlib').Path(sys.argv[3]),__import__('pathlib').Path(sys.argv[4]),sys.argv[5])}))"
    return json.loads(run([PYTHON,"-c",code,wheel,HERE/"run-mcp-catalog-e2e.py",home,repo,needle],env).stdout)

def running(target, executable):
    text = run(["/bin/launchctl","print",target],os.environ).stdout
    assert "state = running" in text and str(executable) in text, text

def main():
    cli, engine, debug_graphd = CLI / "target/debug/axiom-cli", GRAPHD / "target/debug/axiom", GRAPHD / "target/debug/axiom-graphd"
    uid = str(os.getuid()); target = f"gui/{uid}/{LABEL}"
    preflight = subprocess.run(["/bin/launchctl", "print", target], capture_output=True)
    if preflight.returncode == 0: raise RuntimeError(f"refusing pre-existing native label {target}")
    if preflight.returncode != 113: raise RuntimeError(f"unexpected launchctl preflight {preflight.returncode}")
    with tempfile.TemporaryDirectory(prefix="axiom-combined-") as temporary:
        base = Path(temporary); scoped = base / "install-root"; home, fake_home, repo, release = scoped, base/"home", base/"repo", base/"release"
        shutil.copytree(CLI / "evidence/J-005/local-lifecycle-20260922/fixture-template", release)
        (release/"channel.template.json").replace(release/"channel.json")
        run(["uv", "build", "--wheel", "--out-dir", str(release), str(MCP)], os.environ)
        graph_artifact = release/"axiom-graphd-0.0.0-dev.bin"; shutil.copy2(debug_graphd, graph_artifact)
        channel = json.loads((release/"channel.json").read_text())
        for component, file in (("axiom-graphd", graph_artifact), ("axiom-mcp", next(release.glob("axiom_mcp-*.whl")))):
            artifact = next(x for x in channel["components"] if x["component"] == component)["artifacts"][0]
            artifact.update(sha256=digest(file), size_bytes=file.stat().st_size)
        (release/"channel.json").write_text(json.dumps(channel))
        env = os.environ | {"AXIOM_CLI_INSTALL_ROOT":str(scoped), "AXIOM_HOME":str(scoped), "HOME":str(fake_home), "AXIOM_ENGINE_BIN":str(engine), "PATH":f"{PYTHON.parent}:{os.environ['PATH']}"}
        (fake_home / "Library/LaunchAgents").mkdir(parents=True)
        events=[]; plist=fake_home/"Library/LaunchAgents"/f"{LABEL}.plist"
        try:
            install_plan = json.loads(run([cli,"install","--dry-run","--from",release,"--json"],env).stdout)["details"]["plan_digest"]
            events.append(["install-dry-run",0]); run([cli,"install","--apply","--from",release,"--approve-digest",install_plan,"--json"],env); events.append(["install-apply",0])
            install_root = scoped/"installs/ecosystem"; pointer_doc=json.loads((install_root/"current").read_text())
            installed = Path(next(x for x in pointer_doc["activated"] if x["component"]=="axiom-graphd")["destination"])
            assert installed.is_file() and os.access(installed, os.X_OK) and digest(installed)==next(x for x in pointer_doc["activated"] if x["component"]=="axiom-graphd")["sha256"]
            installed_sha = digest(installed)
            (repo/"src").mkdir(parents=True); (home/"config").mkdir(parents=True)
            shutil.copyfile(HERE.parent/"engine-readiness-20260922/sqlite-default-wal-e2e-Demo.cs",repo/"src/Demo.cs")
            (home/"config/bindings.json").write_text(json.dumps({"bindings":{"demo-repo":str(repo)}}))
            solution=scoped/"solution.json"; solution.write_text(json.dumps({"id":"demo-solution","profile":"default","catalog_host_repo":"demo-repo","projects":[{"id":"demo-project","repo_id":"demo-repo","path":"src"}]}))
            run([installed,"solution","register","--config",solution,"--apply","--json"],env); events.append(["register",0])
            run([engine,"service","install","--component","axiom-graphd","--user","--json"],env); events.append(["service-install",0])
            pointer=repo/".axiom/graph/demo-solution/_catalog/live/current.json"; before_id=wait_catalog(pointer)
            installed_wheel = Path(next(x for x in pointer_doc["activated"] if x["component"]=="axiom-mcp")["destination"])
            installed_wheel_sha = digest(installed_wheel)
            before_wrap=query_wheel(installed_wheel,home,repo,"Demo",env); provenance,before=before_wrap["origin"],before_wrap["query"]
            source=repo/"src/Demo.cs"; source.write_text(source.read_text()+"\npublic sealed class LaunchAgentEdit {}\n")
            after_id=wait_catalog(pointer,before_id); after=query_wheel(installed_wheel,home,repo,"LaunchAgentEdit",env)["query"]
            assert before["nodes"] and after["nodes"]
            # Reuse verified payload bytes but assign a development fixture version.  The
            # two generations intentionally contain the same runnable graphd bytes.
            update = scoped / "update-bundle"; shutil.copytree(scoped/"staging/engine-bundle", update)
            bundle = json.loads((update/"bundle.json").read_text())
            bundle["bundle_id"] = "combined-update"; bundle["components"][0]["version"] = "0.0.1-dev"
            (update/"bundle.json").write_text(json.dumps(bundle))
            skills = json.loads((update/"skills/bundle.json").read_text()); skills["version"]="0.1.1"
            (update/"skills/bundle.json").write_text(json.dumps(skills))
            old_core, old_skills = (install_root/"current").read_bytes(), (install_root/"skills/current").read_bytes()
            update_plan=scoped/"update-plan.json"; planned=json.loads(run([engine,"update","plan","--to","0.0.1-dev","--bundle",update,"--out",update_plan,"--json"],env).stdout)
            applied=json.loads(run([engine,"update","apply","--plan",update_plan,"--approve-digest",planned["plan_digest"],"--json"],env).stdout); events.append(["update-apply",0])
            assert (install_root/"current").read_bytes()!=old_core
            new_graph=Path(next(x for x in json.loads((install_root/"current").read_text())["activated"] if x["component"]=="axiom-graphd")["destination"])
            running(target,new_graph); assert query_wheel(installed_wheel,home,repo,"LaunchAgentEdit",env)["query"]["nodes"]
            run([engine,"update","rollback","--transaction",applied["transaction_id"],"--json"],env); events.append(["update-rollback",0])
            assert (install_root/"current").read_bytes()==old_core and (install_root/"skills/current").read_bytes()==old_skills
            running(target,installed); assert query_wheel(installed_wheel,home,repo,"LaunchAgentEdit",env)["query"]["nodes"]
            uninstall_plan=scoped/"uninstall-plan.json"; removal=json.loads(run([engine,"uninstall","plan","--out",uninstall_plan,"--json"],env).stdout)
            user_file=scoped/"user-preserved.txt"; user_file.write_text("user data\n")
            run([engine,"uninstall","apply","--plan",uninstall_plan,"--approve-digest",removal["plan_digest"],"--json"],env); events.append(["engine-uninstall",0])
            assert subprocess.run(["/bin/launchctl","print",target],capture_output=True).returncode == 113 and not plist.exists()
            assert user_file.read_text()=="user data\n" and not any((install_root/"versions").rglob("axiom-graphd"))
            print(json.dumps({"schema_version":1,"scope":"temporary home/install root","events":events,"installed_graphd_sha256":installed_sha,"installed_wheel_sha256":installed_wheel_sha,"installed_wheel_import_verified":provenance.startswith(str(installed_wheel)),"catalog_before":before_id,"catalog_after":after_id,"mcp_before_nodes":len(before["nodes"]),"mcp_after_nodes":len(after["nodes"]),"launchagent":LABEL},sort_keys=True))
        finally:
            subprocess.run(["/bin/launchctl","bootout",target],capture_output=True)
            if plist.exists(): plist.unlink()
    return 0
if __name__ == "__main__": raise SystemExit(main())

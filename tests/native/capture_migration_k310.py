#!/usr/bin/env python3
"""Exercise the actual public migration executable on isolated native roots.

The fixture is an exact, previously engine-produced immutable graph archive.
This tests migration execution on the current OS; it never relabels its producer.
The same program is the Mac Intel reproduction handoff.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--fixture-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--scratch', type=Path, required=True)
    args = parser.parse_args()
    exe, fixture = args.cli.resolve(), args.fixture.resolve()
    assert sha(fixture) == args.fixture_sha256, 'immutable fixture changed'
    out = args.out.resolve()
    assert not out.exists(), 'do not overwrite historical evidence'
    out.mkdir(parents=True)
    args.scratch.mkdir(parents=True, exist_ok=True)
    commands, cases = [], []
    case_start = 0

    def run(root, words, success=True):
        home_path = str(root.parent / (root.name + '-home'))
        if home_path.startswith('\\\\?\\'):
            home_path = home_path[4:]
        env = dict(os.environ, AXIOM_HOME=home_path)
        command = [str(exe), 'migrate', *words, '--json']
        p = subprocess.run(command, cwd=root, env=env, capture_output=True,
                           text=True, encoding='utf-8', timeout=30)
        assert (p.returncode == 0) == success, (words, p.returncode, p.stdout, p.stderr)
        obj = json.loads(p.stdout)
        assert obj.get('code') != 'NOT_READY', 'stub still reachable'
        commands.append(dict(id='command-' + str(len(commands)),
                             argv=['<cli>', 'migrate', *words, '--json'],
                             exit_code=p.returncode, response=obj, stderr=p.stderr))
        return obj

    def record(case):
        nonlocal case_start
        ids = [c['id'] for c in commands[case_start:]]
        assert ids, 'every native case must cite actual commands'
        cases.append(dict(id=case, passed=True, command_ids=ids))
        case_start = len(commands)

    def populate(root, spelling='graph'):
        legacy = root / '.agrimap-agent/knowledge/references' / spelling / 'demo-solution'
        legacy.mkdir(parents=True)
        with tarfile.open(fixture) as archive:
            for member in archive.getmembers():
                parts = Path(member.name).parts
                assert not Path(member.name).is_absolute() and '..' not in parts
                if not parts or parts[0] != 'graph' or member.isdir():
                    continue
                assert member.isfile() and '\\' not in member.name
                target = legacy.joinpath(*parts[1:])
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
        return legacy

    def make_plan(root):
        return run(root, ['plan', '--solution', 'demo-solution', '--out', 'plan.json'])

    def apply(root, plan, success=True):
        return run(root, ['apply', '--plan', 'plan.json', '--approve-digest', plan['plan_digest']], success)

    def hashes(root):
        return {p.relative_to(root).as_posix(): sha(p) for p in root.rglob('*')
                if p.is_file() and p.name != 'solution.lock'}

    scratch = args.scratch.resolve()
    if os.name == 'nt' and not str(scratch).startswith('\\\\?\\'):
        scratch = Path('\\\\?\\' + str(scratch))
    with tempfile.TemporaryDirectory(prefix='axiom-k310-', dir=scratch) as temporary:
        base = Path(temporary)
        assert base.resolve().is_relative_to(scratch.resolve()), 'cleanup root must stay in task scratch'
        root = base / 'fresh'; root.mkdir()
        plan = make_plan(root)
        assert plan['status'] == 'ready' and plan['migration_needed'] is False
        assert not (root / '.axiom').exists() and not (root / '.agrimap-agent').exists()
        apply(root, plan)
        assert run(root, ['status', '--transaction', plan['transaction']])['status'] == 'complete'
        run(root, ['rollback', '--transaction', plan['transaction'], '--approve-digest', plan['plan_digest']])
        record('fresh-plan-apply-status-rollback')

        for spelling in ('graph', 'grahp'):
            root = base / spelling; root.mkdir(); legacy = populate(root, spelling)
            before = hashes(legacy)
            sentinel = root / 'human.txt'; sentinel.write_bytes(b'human-owned\r\n')
            plan = make_plan(root); assert plan['migration_needed'] is True
            assert run(root, ['apply', '--plan', 'plan.json', '--approve-digest', '0' * 64], False)['code'] == 'FORBIDDEN'
            assert not (root / '.axiom/graph').exists()
            apply(root, plan)
            target = root / '.axiom/graph/demo-solution'
            assert hashes(target) == before
            assert apply(root, plan)['status'] == 'already-complete'
            assert run(root, ['status', '--transaction', plan['transaction']])['status'] == 'complete'
            run(root, ['rollback', '--transaction', plan['transaction'], '--approve-digest', plan['plan_digest']])
            assert not hashes(target) and hashes(legacy) == before
            assert sentinel.read_bytes() == b'human-owned\r\n'
            record(spelling + '-import-idempotency-rollback-preservation')

        root = base / 'equal'; root.mkdir(); legacy = populate(root)
        shutil.copytree(legacy.parent, root / '.agrimap-agent/knowledge/references/grahp')
        plan = make_plan(root); apply(root, plan); record('equal-both-spellings')

        root = base / 'conflict'; root.mkdir(); legacy = populate(root)
        shutil.copytree(legacy.parent, root / '.agrimap-agent/knowledge/references/grahp')
        next((root / '.agrimap-agent/knowledge/references/grahp').rglob('manifest.json')).write_bytes(b'corrupt')
        assert run(root, ['plan', '--solution', 'demo-solution'], False)['code'] == 'CONFLICT'
        assert not (root / '.axiom').exists(); record('conflict-corrupt-no-destination-writes')

        root = base / 'unsafe-link'; root.mkdir(); populate(root)
        link = root / '.axiom/graph'; link.parent.mkdir()
        other = base / 'link-target'; other.mkdir(); (other / 'human.txt').write_bytes(b'preserve link target')
        if os.name == 'nt':
            lexical = lambda path: str(path)[4:] if str(path).startswith('\\\\?\\') else str(path)
            p = subprocess.run(['cmd', '/c', 'mklink', '/J', lexical(link), lexical(other)],
                               capture_output=True, text=True)
            assert p.returncode == 0, p.stderr
        else:
            link.symlink_to(other, target_is_directory=True)
        refused = run(root, ['plan', '--solution', 'demo-solution'], False)
        assert 'link/junction' in refused['message']
        assert (other / 'human.txt').read_bytes() == b'preserve link target'
        record('unsafe-link-junction-refused')

        root = base / 'stale'; root.mkdir(); legacy = populate(root)
        plan = make_plan(root); next(legacy.rglob('manifest.json')).write_bytes(b'changed after approval')
        assert apply(root, plan, False)['code'] == 'CONFLICT'; record('source-changed-after-plan')

        root = base / 'target-conflict'; root.mkdir(); populate(root)
        plan = make_plan(root)
        sentinel = root / '.axiom/graph/human.txt'; sentinel.parent.mkdir(parents=True); sentinel.write_bytes(b'keep')
        assert apply(root, plan, False)['code'] == 'CONFLICT'; assert sentinel.read_bytes() == b'keep'; record('target-appeared-preserved')

        root = base / 'resume'; root.mkdir(); legacy = populate(root); plan = make_plan(root)
        # The engine stages using destination paths, not the legacy source path.
        blocker = root / '.axiom/tmp' / plan['transaction'] / 'stage/root/.axiom'
        blocker.parent.mkdir(parents=True); blocker.write_bytes(b'filesystem failure boundary')
        assert apply(root, plan, False)['code'] == 'INTERNAL'
        blocker.unlink()
        assert apply(root, plan)['status'] == 'resumed'; record('native-stage-failure-and-journal-resume')
        target = root / '.axiom/graph/demo-solution'
        changed = next(target.rglob('manifest.json')); original = changed.read_bytes(); changed.write_bytes(b'human edit')
        assert run(root, ['rollback', '--transaction', plan['transaction'], '--approve-digest', plan['plan_digest']], False)['code'] == 'CONFLICT'
        assert changed.read_bytes() == b'human edit'; changed.write_bytes(original)
        run(root, ['rollback', '--transaction', plan['transaction'], '--approve-digest', plan['plan_digest']])
        assert hashes(legacy); record('rollback-refuses-later-human-edit')

        root = base / 'busy'; root.mkdir(); populate(root); plan = make_plan(root)
        apply(root, plan)  # establish the same private home the real executor uses
        home = root.parent / (root.name + '-home')
        lock = home / 'run/daemon.lock'
        if os.name == 'nt':
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                          ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
            kernel.CreateFileW.restype = ctypes.c_void_p
            handle = kernel.CreateFileW(str(lock), 0xC0000000, 0, None, 4, 0x80, None)
            assert handle not in (None, ctypes.c_void_p(-1).value)
            try:
                assert apply(root, plan, False)['code'] == 'WRITER_ALREADY_RUNNING'
            finally:
                kernel.CloseHandle.argtypes = [ctypes.c_void_p]; kernel.CloseHandle(handle)
        else:
            lock.write_bytes(b'live native claim')
            (home / 'run/daemon.owner.json').write_text(json.dumps(dict(format='axiom-daemon-lock-v1',
                holder='native-test-writer', pid=os.getpid(), started_at='test', host=platform.node())))
            assert apply(root, plan, False)['code'] == 'WRITER_ALREADY_RUNNING'
        record('actual-native-writer-claim-refusal')

    # Redact task-local absolute roots without changing committed snapshot inputs.
    report = dict(task_id='K-310', status='ready', certified=False, native_runtime=True,
                  plan_response_paths_redacted=True,
                  environment=dict(os=platform.system(), arch=platform.machine(),
                                   os_version=platform.platform(), uid=os.getuid() if hasattr(os, 'getuid') else None,
                                   execution='wsl2' if 'microsoft' in platform.release().lower() else 'native'),
                  cli_sha256=sha(exe), fixture_sha256=sha(fixture), cases=cases, commands=commands)
    text = json.dumps(report, indent=2)
    text = text.replace(str(base), '<test-root>').replace(str(base).replace('\\', '\\\\'), '<test-root>')
    (out / 'native-report.json').write_text(text + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(dict(task_id='K-310', status='ready', cases=len(cases), commands=len(commands),
                          cli_sha256=sha(exe), fixture_sha256=sha(fixture), environment=report['environment'])))


if __name__ == '__main__':
    main()

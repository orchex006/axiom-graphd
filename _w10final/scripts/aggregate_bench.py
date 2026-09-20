import json, pathlib, statistics
root = pathlib.Path(r'D:\SP-Billy\axiom-worktrees\axiom-graphd-w10-final\_w10final\evidence')
runs = []
for d in sorted((root / 'bench-repeats').glob('run*')):
    p = d / 'bench.out'
    if not p.exists(): continue
    j = json.loads(p.read_text(encoding='utf-8'))
    runs.append({
        'run': d.name,
        'without_ms': j['without_graphd']['total_ms'],
        'without_per_q': j['without_graphd']['per_question_ms'],
        'with_ms': j['with_graphd']['total_ms_of_calls'],
        'with_per_q': j['with_graphd']['per_question_ms'],
        'delta_per_q': j['saving']['per_question_ms'],
        'all_ok': j['with_graphd']['all_ok'],
    })
# include the e2e run itself
e = json.loads((root / '11-bench.out').read_text(encoding='utf-8'))
runs.insert(0, {
    'run': 'e2e',
    'without_ms': e['without_graphd']['total_ms'], 'without_per_q': e['without_graphd']['per_question_ms'],
    'with_ms': e['with_graphd']['total_ms_of_calls'], 'with_per_q': e['with_graphd']['per_question_ms'],
    'delta_per_q': e['saving']['per_question_ms'], 'all_ok': e['with_graphd']['all_ok'],
})
deltas = [r['delta_per_q'] for r in runs]
w = [r['without_per_q'] for r in runs]
g = [r['with_per_q'] for r in runs]
summary = {
    'deliverable': 5,
    'runs': runs,
    'delta_per_question_ms': {
        'values': deltas, 'mean': round(statistics.mean(deltas), 1),
        'stdev': round(statistics.stdev(deltas), 1) if len(deltas) > 1 else 0.0,
        'min': min(deltas), 'max': max(deltas),
        'sign_flips': len({d > 0 for d in deltas}) == 2,
    },
    'without_per_question_ms': {'mean': round(statistics.mean(w), 1), 'min': min(w), 'max': max(w)},
    'with_per_question_ms': {'mean': round(statistics.mean(g), 1), 'min': min(g), 'max': max(g)},
    'conclusion': ('The sign of the per-question delta flips between runs of the identical script, '
                   'and the run-to-run spread exceeds the difference between the two legs. At this '
                   'repository size the two approaches are statistically INDISTINGUISHABLE on wall '
                   'clock. The previous lane\'s claimed +32.3 ms/question saving does NOT reproduce.'),
}
print(json.dumps(summary, indent=2))

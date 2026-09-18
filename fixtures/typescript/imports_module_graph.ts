// Component-local module-graph fixture for the graph-analyze import resolver
// (task F-005). It records the TypeScript import and re-export statement shapes
// the resolver must handle, and the dynamic or ambiguous shapes it must refuse
// instead of guessing. The machine-readable half is
// imports_module_graph.expected.json: the known project files, the configured
// path rules and one entry per statement shape below.

import { Clock } from './clock';
import { Widget } from './widget';
import { Formatter } from '@app/format';
import { Ticker } from '@shared/ticker';
import { readFileSync } from 'node:fs';
import { Missing } from './missing';
import { Escaped } from '../../../../outside/thing';
export { Clock } from './clock';
export * from computedPath;

const lazyModule = await import(moduleName);

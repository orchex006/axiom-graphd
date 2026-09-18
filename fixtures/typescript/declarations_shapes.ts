// Component-local TypeScript declaration fixture for
// graph_analyze::typescript::declarations (task F-005). An explicitly named
// declaration, an anonymous default export and a computed binding must be
// separated: nothing is given a name the source does not carry. The
// machine-readable half is declarations_shapes.expected.json.

export interface Id {
  value: string;
}

export class Widget {
  label = 'w';
}

export type Alias = string;

export const { left, right } = pair;

export default class {
}

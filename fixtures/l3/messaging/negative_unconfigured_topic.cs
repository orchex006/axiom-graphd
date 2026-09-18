// Static fixture: a literal topic the operator never configured in the solution.
await bus.Publish("shipments.untracked", message);

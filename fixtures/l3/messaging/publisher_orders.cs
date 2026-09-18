// Static fixture: a literal producer on a configured topic.
await bus.PublishAsync("orders.created", message);

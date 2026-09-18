// Static fixture: a literal producer for the shipping topic.
await queue.SendAsync("shipments.queued", message);

// Static fixture: topics computed at runtime must stay unresolved.
await bus.PublishAsync(topicName, message);
await bus.Publish($"orders.{tenant}", message);

[KafkaTopic(topicName)]
public class DynamicConsumer : IConsumer<OrderCreated> { }

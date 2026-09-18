// Static fixture: a literal consumer call and a literal topic attribute.
bus.Subscribe("orders.created");

[ServiceBusQueue("shipments.queued")]
public class ShipmentConsumer : IConsumer<ShipmentQueued> { }

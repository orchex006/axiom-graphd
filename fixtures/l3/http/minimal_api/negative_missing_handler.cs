// Static fixture: a mapping without a request delegate.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/items");

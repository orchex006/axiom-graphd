// Static fixture: the route pattern is computed at runtime.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet(itemPath, () => Results.Ok());

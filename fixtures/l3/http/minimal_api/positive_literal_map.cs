// Static fixture: literal minimal API mappings on a built WebApplication root.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/items", () => Results.Ok());

var group = app.MapGroup("/api/v1");
group.MapPost("/items", () => Results.Created());

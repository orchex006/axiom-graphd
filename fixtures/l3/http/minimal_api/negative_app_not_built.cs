// Static fixture: a mapping on a builder that was never built.
var builder = WebApplication.CreateBuilder(args);

builder.MapGet("/items", () => Results.Ok());

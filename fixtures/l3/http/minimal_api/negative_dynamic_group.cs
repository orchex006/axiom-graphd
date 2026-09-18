// Static fixture: the MapGroup prefix is computed at runtime.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var group = app.MapGroup(prefix);

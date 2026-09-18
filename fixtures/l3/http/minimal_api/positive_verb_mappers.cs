// Static fixture: every verb mapper the minimal API adapter supports.
// Source text only; nothing here is executed and no runtime log is involved.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapPut("/items/{id}", (string id) => Results.NoContent());
app.MapDelete("/items/{id}", (string id) => Results.NoContent());
app.MapPatch("/items/{id}", (string id) => Results.NoContent());

// Static fixture: the five convention-driven mappers this adapter refuses.
// Each line is one declared convention pattern; none may become an endpoint.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapRazorPages();
app.MapHub("/hubs/chat");
app.MapHealthChecks("/healthz");
app.MapFallback(() => Results.NotFound());
app.MapMethods("/items", new[] { "GET", "HEAD" }, () => Results.Ok());

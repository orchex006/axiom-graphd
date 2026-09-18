// Static boundary fixture: the generic MapHub<T> spelling.
// The adapter only recognises `MapHub(` with the parenthesis directly after the
// name, so this line must produce no endpoint and no refusal at all - it must
// never be mis-parsed into a wrong endpoint.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapHub<ChatHub>("/hubs/chat");

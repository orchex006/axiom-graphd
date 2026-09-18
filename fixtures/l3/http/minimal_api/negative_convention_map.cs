// Static fixture: convention-driven endpoint discovery is not analysed.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapControllers();

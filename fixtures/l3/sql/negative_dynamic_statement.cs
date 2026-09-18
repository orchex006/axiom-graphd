// Static fixture: SQL assembled at runtime must stay unresolved.
var a = $"SELECT Id FROM dbo.Items WHERE Id = {id}";
var b = "SELECT Id FROM dbo.Items WHERE Id = " + id;

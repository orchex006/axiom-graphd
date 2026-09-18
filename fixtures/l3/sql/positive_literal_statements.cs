// Static fixture: literal SQL statements the adapter must analyse.
// Source text only; no statement is ever executed and no runtime log is involved.
var select = "SELECT Id, Name FROM dbo.Items";
var insert = "INSERT INTO Customers (Name) VALUES ('x')";
var update = "UPDATE Orders SET Status = 1";
var delete = "DELETE FROM Sessions";
var exec = "EXEC dbo.RebuildIndexes";

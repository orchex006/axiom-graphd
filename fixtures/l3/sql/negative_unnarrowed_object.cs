// Static fixture: a literal statement whose target cannot be narrowed.
var derived = "SELECT * FROM (SELECT 1) t";
var parameterised = "EXEC @procName";

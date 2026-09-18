// Static fixture: the controller route prefix is a computed expression.
// The adapter must refuse both the controller prefix and its action.
using Microsoft.AspNetCore.Mvc;

namespace Fixtures;

[Route($"api/{version}")]
public class VersionedController : ControllerBase
{
    [HttpGet("list")]
    public IActionResult List() => Ok();
}

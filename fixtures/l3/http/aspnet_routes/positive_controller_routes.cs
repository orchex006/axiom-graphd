// Static fixture: literal ASP.NET controller route attributes.
// Source text only. Nothing here is executed and no runtime log is involved.
using Microsoft.AspNetCore.Mvc;

namespace Fixtures;

[ApiController]
[Route("api/[controller]")]
public class ItemsController : ControllerBase
{
    [HttpGet("{id}")]
    public IActionResult GetItem(int id) => Ok(id);

    [HttpPost]
    public IActionResult Create([FromBody] Item item) { return Ok(item); }
}

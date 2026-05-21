// Expected: no finding (safe — has [Authorize] attribute)
// ASP.NET Core controller with proper authorization
[ApiController]
[Route("api/admin")]
[Authorize(Roles = "Admin")]
public class AdminController : ControllerBase
{
    [HttpGet("users")]
    public IActionResult GetUsers()
    {
        var users = _db.Users.ToList();
        return Ok(users);
    }

    [HttpPost("users")]
    public IActionResult CreateUser([FromBody] UserDto user)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        _db.Users.Add(user);
        _db.SaveChanges();
        return CreatedAtAction(nameof(GetUsers), new { id = user.Id }, user);
    }
}

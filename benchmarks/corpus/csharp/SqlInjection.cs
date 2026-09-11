using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

public class UsersController : Controller
{
    public IActionResult Lookup(string name)
    {
        var conn = new SqlConnection(ConnStr);
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'", conn);
        cmd.ExecuteReader();
        return Ok();
    }
}

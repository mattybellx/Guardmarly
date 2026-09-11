using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class ToolsController : Controller
{
    public IActionResult Ping(string host)
    {
        Process.Start("cmd.exe", "/c ping -c 1 " + host);
        return Ok();
    }
}

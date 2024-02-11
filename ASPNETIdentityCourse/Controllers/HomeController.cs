using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using ASPNETIdentityCourse.Models;
using ASPNETIdentityCourse.Models.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace ASPNETIdentityCourse.Controllers;

public class HomeController(ILogger<HomeController> logger, UserManager<ApplicationUser> userManager)
    : Controller
{
    private readonly ILogger<HomeController> _logger = logger;
    private readonly UserManager<ApplicationUser> _userManager = userManager;

    public async Task<IActionResult> Index()
    {
        var user = await _userManager.GetUserAsync(User);

        if (user is null)
        {
            ViewData["TwoFactorEnabled"] = false;
        }
        else
        {
            ViewData["TwoFactorEnabled"] = user.TwoFactorEnabled;
        }

        return View();
    }

    [Authorize]
    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
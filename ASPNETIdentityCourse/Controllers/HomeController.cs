using System.Diagnostics;
using ASPNETIdentityCourse.Const;
using Microsoft.AspNetCore.Mvc;
using ASPNETIdentityCourse.Models;
using ASPNETIdentityCourse.Models.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Unleash;

namespace ASPNETIdentityCourse.Controllers;

public class HomeController(ILogger<HomeController> logger, UserManager<ApplicationUser> userManager, IUnleash unleash)
    : Controller
{
    public async Task<IActionResult> Index()
    {
        var user = await userManager.GetUserAsync(User);

        if (unleash.IsEnabled("kami-console-log"))
        {
            Console.Write("Console Log Feature");
        }

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

    [Authorize(Roles = Role.Administrator)]
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
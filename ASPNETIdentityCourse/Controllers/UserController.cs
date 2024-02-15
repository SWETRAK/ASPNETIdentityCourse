using ASPNETIdentityCourse.Models.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Unleash;

namespace ASPNETIdentityCourse.Controllers;

public class UserController(UserManager<ApplicationUser> userManager, ApplicationDbContext context, IUnleash unleash)
    : Controller
{
    public async  Task<IActionResult> Index()
    {
        var user =  await context.ApplicationUsers.ToListAsync();
        
        return View();
    }
}
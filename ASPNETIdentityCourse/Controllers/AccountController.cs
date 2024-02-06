using ASPNETIdentityCourse.Models.Entities;
using ASPNETIdentityCourse.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ASPNETIdentityCourse.Controllers;

public class AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
    : Controller
{
    public IActionResult Register()
    {
        var registerViewModel = new RegisterViewModel();
        return View(registerViewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel registerViewModel)
    {
        if (!ModelState.IsValid) return View(registerViewModel);

        var user = new ApplicationUser
        {
            UserName = registerViewModel.Email,
            Email = registerViewModel.Email,
            Name = registerViewModel.Name
        };

        var result = await userManager.CreateAsync(user, registerViewModel.Password);

        if (!result.Succeeded) return View(registerViewModel);
        await signInManager.SignInAsync(user, isPersistent: false);
        return RedirectToAction("Index", "Home");
    }
}
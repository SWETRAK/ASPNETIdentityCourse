using ASPNETIdentityCourse.Models.Entities;
using ASPNETIdentityCourse.Models.ViewModels;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;

namespace ASPNETIdentityCourse.Controllers;

public class AccountController(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    // IEmailSender emailSender,
    IMapper mapper)
    : Controller
{

    #region Register

    [HttpGet]
    public IActionResult Register(string returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        var registerViewModel = new RegisterViewModel();
        return View(registerViewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel registerViewModel, string returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        returnUrl ??= Url.Content("/");
        if (!ModelState.IsValid) return View(registerViewModel);

        var user = mapper.Map<ApplicationUser>(registerViewModel);
        var result = await userManager.CreateAsync(user, registerViewModel.Password);

        if (!result.Succeeded)
        {
            AddErrors(result);
            return View(registerViewModel);
        }

        var code = await userManager.GenerateEmailConfirmationTokenAsync(user);
        var callbackUrl = Url.Action(
            "ConfirmEmail", 
            "Account", 
            new
            {
                userId = user.Id, 
                code = code
            },
            protocol: HttpContext.Request.Scheme);
        
        // There should be send email with email confirmation url
        Console.WriteLine(callbackUrl);
        
        await signInManager.SignInAsync(user, isPersistent: false);
        return LocalRedirect(returnUrl);
    }

    #endregion

    #region Login
        
    [HttpGet]
    public IActionResult Login(string returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        var loginViewModel = new LoginViewModel();
        return View(loginViewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel loginViewModel, string returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        returnUrl ??= Url.Content("/");

        if (!ModelState.IsValid) return View(loginViewModel);

        var result = await signInManager.PasswordSignInAsync(loginViewModel.Email, loginViewModel.Password,
            loginViewModel.RememberMe, true);

        if (!result.Succeeded)
        {
            return result.IsLockedOut ? View("Lockout") : View(loginViewModel);
        }

        ModelState.AddModelError(string.Empty, "Invalid login attempt");
        return LocalRedirect(returnUrl);
    }

    #endregion
    
    #region ForgotPassword 
    
    [HttpGet]
    public IActionResult ForgotPassword()
    {
        var forgotPasswordViewModel = new ForgotPasswordViewModel();
        return View(forgotPasswordViewModel);
    }
    
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel forgotPasswordViewModel)
    {
        if (!ModelState.IsValid) return View(forgotPasswordViewModel);
        var user = await userManager.FindByEmailAsync(forgotPasswordViewModel.Email);
        if (user is null)
        {
            return RedirectToAction("ForgotPasswordConfirmation");
        }

        var code = await userManager.GeneratePasswordResetTokenAsync(user);
        var callbackUrl = Url.Action(
            "ResetPassword", 
            "Account", 
            new
            {
                userId = user.Id, 
                code = code
            },
            protocol: HttpContext.Request.Scheme);

        Console.Write(callbackUrl);
        // await emailSender.SendEmailAsync(forgotPasswordViewModel.Email, "Reset password", $"url");
        return RedirectToAction(nameof(ForgotPasswordConfirmation));
    }
    
    [HttpGet]
    public IActionResult ForgotPasswordConfirmation()
    {
        return View();
    }
    
    #endregion

    #region ResetPassword

    [HttpGet]
    public IActionResult ResetPassword(string code = null)
    {
        var resetPasswordViewModel = new ResetPasswordViewModel()
        {
            Code = code
        };
        return code is null ? View("Error") : View(resetPasswordViewModel);
    }
    
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel resetPasswordViewModel)
    {
        if (!ModelState.IsValid) return View();
        var user = await userManager.FindByEmailAsync(resetPasswordViewModel.Email);
        if (user is null)
        {
            return RedirectToAction(nameof(ResetPasswordConfirmation));
        }

        var result = await userManager.ResetPasswordAsync(user, resetPasswordViewModel.Code, resetPasswordViewModel.Password);
        if (result.Succeeded)
        {
            return RedirectToAction(nameof(ResetPasswordConfirmation));
        }
        AddErrors(result);

        return View();
    }
    
    [HttpGet]
    public IActionResult ResetPasswordConfirmation()
    {
        return View();
    }
    
    #endregion

    
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LogOff()
    {
        await signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }

    [HttpGet]
    public IActionResult Lockout()
    {
        return View();
    }
    
    [HttpGet]
    public async Task<IActionResult> ConfirmEmail(string userId, string code)
    {
        if (!ModelState.IsValid) return View("Error");
        var user = await userManager.FindByIdAsync(userId);
        if (user is null)
        {
            return View("Error");
        }

        var result = await userManager.ConfirmEmailAsync(user, code);
        return result.Succeeded ? View() : View("Error");

    }
    
    private void AddErrors(IdentityResult identityResult)
    {
        foreach (var error in identityResult.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }
    }
}
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace ASPNETIdentityCourse.Models.ViewModels;

public class RegisterViewModel
{
    [Required] 
    public string Name { get; set; }

    [Required]
    [EmailAddress] 
    public string Email { get; set; }

    [Required]
    [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string Password { get; set; }

    [DataType(DataType.Password)]
    [Display(Name = "Confirm Password")]
    [Compare(nameof(Password), ErrorMessage = "The password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; }
    
    public List<SelectListItem> RoleList { get; set; }
    
    [Display(Name = "Role")]
    public string SelectedRole { get; set; }
    
    
}
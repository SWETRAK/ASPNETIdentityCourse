using System.ComponentModel.DataAnnotations;

namespace ASPNETIdentityCourse.Models.ViewModels;

public class ForgotPasswordViewModel
{
    [Required, EmailAddress]
    public string Email { get; set; }
}
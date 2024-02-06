using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace ASPNETIdentityCourse.Models.Entities;

public class ApplicationUser: IdentityUser
{
    [Required]
    public string Name { get; set; }
}
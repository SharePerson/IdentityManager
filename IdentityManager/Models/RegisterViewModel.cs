using Microsoft.AspNetCore.Mvc.Rendering;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models
{
    public class RegisterViewModel
    {
        [Required]
        public string Name { set; get; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { set; get; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        public string Password { set; get; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        [Compare(nameof(Password), ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { set; get; }

        [Display(Name = "User Role")]
        public string RoleId { get; set; }
    }
}

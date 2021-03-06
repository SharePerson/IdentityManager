using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models
{
    public class ResetPasswordViewModel
    {
        public string Code { set; get; }

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
    }
}

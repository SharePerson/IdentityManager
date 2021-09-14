using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models
{
    public class LoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { set; get; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { set; get; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { set; get; }
    }
}

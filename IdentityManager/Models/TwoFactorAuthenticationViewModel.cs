namespace IdentityManager.Models
{
    public class TwoFactorAuthenticationViewModel
    {
        //used to login
        public string Code { get; set; }

        //used to register
        public string Token { get; set; }

        public string QrCodeUrl { set; get; }
    }
}

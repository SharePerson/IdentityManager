using IdentityManager.Controllers.Base;
using IdentityManager.Models;
using IdentityManager.Utilities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace IdentityManager.Controllers
{
    public class AccountController : BaseController
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly IEmailSender emailSender;
        private readonly UrlEncoder urlEncoder;
        private readonly RoleManager<IdentityRole> roleManager;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IEmailSender emailSender, UrlEncoder urlEncoder, RoleManager<IdentityRole> roleManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.emailSender = emailSender;
            this.urlEncoder = urlEncoder;
            this.roleManager = roleManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Register()
        {
            if(!await roleManager.RoleExistsAsync("Admin"))
            {
                await roleManager.CreateAsync(new IdentityRole("Admin"));
                await roleManager.CreateAsync(new IdentityRole("User"));
            }

            ViewBag.RoleList = roleManager.Roles.ToList().ToSelectListItem("Name");

            RegisterViewModel registerViewModel = new();
            return View(registerViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel registerViewModel)
        {
            if(ModelState.IsValid)
            {
                ApplicationUser user = new()
                {
                    UserName = registerViewModel.Email,
                    Email = registerViewModel.Email,
                    Name = registerViewModel.Name
                };

                IdentityResult result = await userManager.CreateAsync(user, registerViewModel.Password);

                if(result.Succeeded)
                {
                    IdentityRole selectedRole = roleManager.Roles.Where(r => r.Id == registerViewModel.RoleId).FirstOrDefault();
                    IdentityResult roleResult = await userManager.AddToRoleAsync(user, selectedRole.Name);

                    if(roleResult.Succeeded)
                    {
                        await signInManager.SignInAsync(user, false);
                        return RedirectToAction("index", "home");
                    }

                    ModelState.AddModelError(string.Empty, $"Failed to assign the {selectedRole.Name} role to the user.");
                    return View(registerViewModel);
                }
                else
                {
                    AddErrors(result);
                }
            }

            return View(registerViewModel);
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> LogOut()
        {
            await signInManager.SignOutAsync();
            return RedirectToAction("index", "home");
        }

        public IActionResult Login(string ReturnUrl = null)
        {
            ViewData["ReturnUrl"] = ReturnUrl;
            LoginViewModel loginViewModel = new();
            return View(loginViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel loginViewModel, string ReturnUrl = null)
        {
            ViewData["ReturnUrl"] = ReturnUrl;

            if (ModelState.IsValid)
            {
                 Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.PasswordSignInAsync(loginViewModel.Email, loginViewModel.Password, loginViewModel.RememberMe, true);

                if(result.Succeeded)
                {
                    if (!string.IsNullOrEmpty(ReturnUrl))
                    {
                        //protection again open redirect attacks
                        return LocalRedirect(ReturnUrl);
                    }

                    return RedirectToAction("index", "home");
                }

                if(result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(VerifyAuthenticatorCode), new { ReturnUrl, loginViewModel.RememberMe });
                }

                if (result.IsLockedOut)
                {
                    ModelState.AddModelError(string.Empty, "You have been locked out. Please contact support!");
                }

                if (result.IsNotAllowed)
                {
                    ModelState.AddModelError(string.Empty, "You are not allowed to login. Please contact support!");
                }

                if (!result.IsNotAllowed && !result.IsLockedOut)
                {
                    ModelState.AddModelError(string.Empty, "Invalid login credentials!");
                }
            }

            return View(loginViewModel);
        }


        public IActionResult ForgotPassword()
        {

            ForgotPasswordViewModel forgotPasswordViewModel = new();
            return View(forgotPasswordViewModel);
        }

        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel forgotPasswordViewModel)
        {
            if(ModelState.IsValid)
            {
                IdentityUser user = await userManager.FindByEmailAsync(forgotPasswordViewModel.Email);

                if(user != null)
                {
                    string code = await userManager.GeneratePasswordResetTokenAsync(user);

                    string resetPasswordLink = Url.Action("ResetPassword", new { Id = code, userId = user.Id });

                    StringBuilder builder = new();
                    builder.Append("Reset your password with ");
                    builder.Append("<a href=" + resetPasswordLink + ">this link</a>");
                    await emailSender.SendEmailAsync(forgotPasswordViewModel.Email, "Reset your password here!", builder.ToString());

                    return RedirectToAction(nameof(ForgotPasswordConfirmation));
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "User is not found in the system");
                }
            }

            return View(forgotPasswordViewModel);
        }

        public IActionResult ResetPassword()
        {

            ResetPasswordViewModel resetPasswordViewModel = new();
            return View(resetPasswordViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel resetPasswordViewModel)
        {
            if (ModelState.IsValid)
            {
                IdentityUser user = await userManager.FindByEmailAsync(resetPasswordViewModel.Email);

                if (user != null)
                {
                    IdentityResult result = await userManager.ResetPasswordAsync(user, resetPasswordViewModel.Code, resetPasswordViewModel.Password);

                    if(result.Succeeded)
                    {
                        return RedirectToAction(nameof(ForgotPasswordConfirmation));
                    }

                    AddErrors(result);
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "User is not found in the system");
                }
            }

            return View(resetPasswordViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string ReturnUrl = null)
        {
            string redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl });
            AuthenticationProperties properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            //needs investigation
            return Challenge(properties, provider);
        }

        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback(string ReturnUrl = null, string remoteError = null)
        {
            if(!string.IsNullOrEmpty(remoteError))
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
                return View(nameof(Login));
            }

            ExternalLoginInfo externalLoginInfo = await signInManager.GetExternalLoginInfoAsync();

            if(externalLoginInfo == null)
            {
                return RedirectToAction(nameof(Login));
            }

            //sign the user in if he has an account in the system!!!!!!
            Microsoft.AspNetCore.Identity.SignInResult signInResult = await signInManager.ExternalLoginSignInAsync(externalLoginInfo.LoginProvider, externalLoginInfo.ProviderKey, false);

            if (signInResult.Succeeded)
            {
                //set auth token
                await signInManager.UpdateExternalAuthenticationTokensAsync(externalLoginInfo);
                return Redirect(ReturnUrl);
            }

            if(signInResult.RequiresTwoFactor)
            {
                return RedirectToAction("VerifyAuthenticatorCode", new { ReturnUrl });
            }

            //if he user does not have an account
            ViewData["ReturnUrl"] = ReturnUrl;
            ViewData["ProviderDisplayName"] = externalLoginInfo.ProviderDisplayName;

            //retrieve email from external login provider
            string email = externalLoginInfo.Principal.FindFirstValue(ClaimTypes.Email);

            //retrieve name from external login provider
            string name = externalLoginInfo.Principal.FindFirstValue(ClaimTypes.Name);

            ApplicationUser user = new()
            {
                UserName = email,
                Email = email,
                Name = name
            };

            await userManager.CreateAsync(user);

            IdentityRole userRole = roleManager.Roles.FirstOrDefault(r => r.Name.ToLower() == "user");
            await userManager.AddToRoleAsync(user, userRole.Name);

            return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = email, Name = name });
        }

        public async Task<IActionResult> EnableAuthenticator()
        {
            //needed for QR code generation
            string authenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

            IdentityUser user = await userManager.GetUserAsync(User);

            //reset all existing keys for that logged in user
            await userManager.ResetAuthenticatorKeyAsync(user);
            string token = await userManager.GetAuthenticatorKeyAsync(user);

            //needed for QR code generation
            //first param: The name of the app that will be displayed on the authenticator app.
            //second param: The email (or could be the name) of the user associated with the app name 
            //that will be displayed on the authenticator app.
            string authenticatorUri = string.Format(authenticatorUriFormat, urlEncoder.Encode("IdentityManager"),
                urlEncoder.Encode(user.Email), token);

            return View(new TwoFactorAuthenticationViewModel { Token = token, QrCodeUrl = authenticatorUri });
        }

        public async Task<IActionResult> RemoveAuthenticator()
        {
            IdentityUser user = await userManager.GetUserAsync(User);

            //reset all existing keys for that logged in user
            await userManager.ResetAuthenticatorKeyAsync(user);
            await userManager.SetTwoFactorEnabledAsync(user, false);

            return RedirectToAction(nameof(Index), "Home");
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationViewModel model)
        {
            if(ModelState.IsValid)
            {
                IdentityUser user = await userManager.GetUserAsync(User);

                string tokenProvider = userManager.Options.Tokens.AuthenticatorTokenProvider;

                bool succeeded = await userManager.VerifyTwoFactorTokenAsync(user, tokenProvider, model.Code);

                if(succeeded)
                {
                    await userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError("Verify", "Invalid TFA code!");
                    return View(model);
                }
            }

            return RedirectToAction("TFAConfirmation");
        }

        [Authorize]
        public IActionResult TFAConfirmation()
        {
            return View();
        }

        public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string ReturnUrl = null)
        {
            IdentityUser user = await signInManager.GetTwoFactorAuthenticationUserAsync();

            if(user == null)
            {
                return View("Error");
            }

            ViewData["ReturnUrl"] = ReturnUrl;

            return View(new VerifyAuthenticatorViewModel { ReturnUrl = ReturnUrl, RememberMe = rememberMe });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorViewModel model)
        {
            model.ReturnUrl ??= Url.Content("~/");

            if (!ModelState.IsValid) return View(model);

            Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberMe, rememberClient: true);

            if(result.Succeeded)
            {
                return LocalRedirect(model.ReturnUrl);
            }

            if(result.IsLockedOut)
            {
                return View("Lockout");
            }

            ModelState.AddModelError(string.Empty, "Invalid TFA Code");
            return View(model);
        }
    }
}

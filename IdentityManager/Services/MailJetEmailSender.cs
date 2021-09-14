using Mailjet.Client;
using Mailjet.Client.Resources;
using Mailjet.Client.TransactionalEmails;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json.Linq;
using System.Threading.Tasks;

namespace IdentityManager.Services
{
    public class MailJetEmailSender : IEmailSender
    {
        private readonly IConfiguration configuration;

        public MailJetEmailSender(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            MailJetOptions mailJetOptions = configuration.GetSection("MailJet").Get<MailJetOptions>();

            MailjetClient client = new(mailJetOptions.ApiKey, mailJetOptions.SecretKey);

            MailjetRequest request = new MailjetRequest
            {
                Resource = Send.Resource,
            } .Property(Send.Messages, new JArray { new JObject { { "From", new JObject { {"Email", "support@identitymanager.com"}, {"Name", "Identity Manager"} } }, { "To", new JArray { new JObject { { "Email", email }, { "Name", email } } } }, { "Subject", subject }, { "HTMLPart", htmlMessage }}});
            
            
            _ = await client.PostAsync(request);
        }
    }
}

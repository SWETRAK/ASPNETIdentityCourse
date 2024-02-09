// using System.Net;
// using System.Net.Mail;
// using ASPNETIdentityCourse.Models.Configuration;
// using Microsoft.AspNetCore.Identity.UI.Services;
//
// namespace ASPNETIdentityCourse.Services;
//
// public class EmailSenderService: IEmailSender
// {
//     private readonly SmtpClient _smtpClient;
//
//     public EmailSenderService(IConfiguration configuration)
//     {
//         var googleMailConfiguration = new GoogleMailConfiguration();
//         configuration.Bind("GoogleMail", googleMailConfiguration);
//         
//         _smtpClient = new SmtpClient
//         {
//             Port = 12324,
//             Credentials = new NetworkCredential("email", "password"),
//             Host = configuration.GetConnectionString("Gmail"),
//             EnableSsl = false
//         };
//     }
//
//     public Task SendEmailAsync(string email, string subject, string htmlMessage)
//     {
//         var mailMessage = new MailMessage
//         {
//             From = new MailAddress(""),
//             Subject = subject,
//             Body = htmlMessage,
//             IsBodyHtml = true,
//             To = { email }
//         };
//         
//         _smtpClient.Send(mailMessage);
//         
//         return Task.CompletedTask;
//     }
// }
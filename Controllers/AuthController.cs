using System;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AceAgencyMembership.Data;
using AceAgencyMembership.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Http;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;

namespace AceAgencyMembership.Controllers
{
    public class AuthController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;

        public AuthController(ApplicationDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            var email = HttpContext.Session.GetString("UserEmail");
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

            if (!string.IsNullOrEmpty(email))
            {
                _context.AuditLogs.Add(new AuditLog { Action = "Logout", Email = email, IPAddress = ipAddress });
                await _context.SaveChangesAsync();
            }

            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

        [HttpPost]
        public async Task<IActionResult> Login(string email, string password, string recaptchaToken)
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

            // Verify ReCaptcha before proceeding
            if (!await VerifyReCaptcha(recaptchaToken))
            {
                ModelState.AddModelError("Recaptcha", "ReCaptcha validation failed.");
                return View();
            }

            var member = await _context.Members.FirstOrDefaultAsync(m => m.Email == email);

            if (member == null)
            {
                _context.AuditLogs.Add(new AuditLog { Action = "Failed Login", Email = email, IPAddress = ipAddress });
                await _context.SaveChangesAsync();
                ModelState.AddModelError("Email", "Invalid email or password.");
                return View();
            }

            if (member.IsLocked && member.LockoutEnd > DateTime.UtcNow)
            {
                _context.AuditLogs.Add(new AuditLog { Action = "Account Locked", Email = email, IPAddress = ipAddress });
                await _context.SaveChangesAsync();
                ModelState.AddModelError("Email", $"Account locked. Try again after {member.LockoutEnd}.");
                return View();
            }

            if (!VerifyPassword(password, member.PasswordHash))
            {
                member.FailedLoginAttempts++;

                if (member.FailedLoginAttempts >= 3)
                {
                    member.LockAccount(DateTime.UtcNow.AddMinutes(10));
                    _context.AuditLogs.Add(new AuditLog { Action = "Account Locked", Email = email, IPAddress = ipAddress });
                }
                else
                {
                    _context.AuditLogs.Add(new AuditLog { Action = "Failed Login", Email = email, IPAddress = ipAddress });
                }

                await _context.SaveChangesAsync();
                ModelState.AddModelError("Email", "Invalid email or password.");
                return View();
            }

            // Successful login
            member.FailedLoginAttempts = 0;
            member.UnlockAccount();
            await _context.SaveChangesAsync();

            HttpContext.Session.SetString("UserEmail", member.Email);
            HttpContext.Session.SetString("UserId", member.Id.ToString());

            _context.AuditLogs.Add(new AuditLog { Action = "Successful Login", Email = email, IPAddress = ipAddress });
            await _context.SaveChangesAsync();

            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public IActionResult ForgotPassword(string email)
        {
            var member = _context.Members.FirstOrDefault(m => m.Email == email);
            if (member == null)
            {
                ModelState.AddModelError("Email", "Email not found.");
                return View();
            }

            // Generate a reset token (for simplicity, store a GUID)
            var resetToken = Guid.NewGuid().ToString();
            HttpContext.Session.SetString("PasswordResetToken", resetToken);
            HttpContext.Session.SetString("ResetEmail", email);

            // Simulate sending email
            ViewData["Message"] = $"Use this token: {resetToken} to reset your password.";

            return View();
        }


        private async Task<bool> VerifyReCaptcha(string token)
        {
            var secretKey = _configuration["GoogleReCaptcha:SecretKey"];

            using var client = new HttpClient();
            var values = new Dictionary<string, string>
            {
                { "secret", secretKey },
                { "response", token }
            };

            var content = new FormUrlEncodedContent(values);
            var response = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
            var jsonResponse = await response.Content.ReadAsStringAsync();

            using var doc = JsonDocument.Parse(jsonResponse);
            return doc.RootElement.GetProperty("success").GetBoolean();
        }

        private static bool VerifyPassword(string password, string storedHash)
        {
            if (string.IsNullOrEmpty(storedHash)) return false;

            try
            {
                byte[] salt = new byte[16];
                byte[] hashBytes = Convert.FromBase64String(storedHash);

                if (hashBytes.Length < 32) return false;

                Array.Copy(hashBytes, 0, salt, 0, 16);

                byte[] hash = KeyDerivation.Pbkdf2(
                    password: password,
                    salt: salt,
                    prf: KeyDerivationPrf.HMACSHA256,
                    iterationCount: 100000,
                    numBytesRequested: 32);

                for (int i = 0; i < 32; i++)
                {
                    if (hashBytes[i + 16] != hash[i]) return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}

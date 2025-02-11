using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AceAgencyMembership.Data;
using AceAgencyMembership.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Http;
using System.Text.Json;
using Microsoft.Extensions.Configuration; // Import for configuration

namespace AceAgencyMembership.Controllers
{
    public class AuthController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration; // Inject configuration

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
        public IActionResult Logout()
        {
            HttpContext.Session.Clear(); // Clear session
            return RedirectToAction("Login");
        }

        [HttpPost]
        public async Task<IActionResult> Login(string email, string password, string recaptchaToken)
        {
            if (!await VerifyReCaptcha(recaptchaToken))
            {
                ModelState.AddModelError("Captcha", "reCAPTCHA validation failed.");
                return View();
            }

            var member = _context.Members.FirstOrDefault(m => m.Email == email);

            if (member == null)
            {
                ModelState.AddModelError("Email", "Invalid email or password.");
                return View();
            }

            // Check if the account is locked
            if (member.IsLocked && member.LockoutEnd > DateTime.UtcNow)
            {
                ModelState.AddModelError("Email", $"Account locked. Try again after {member.LockoutEnd}.");
                return View();
            }

            // Verify the password
            if (!VerifyPassword(password, member.PasswordHash))
            {
                member.FailedLoginAttempts++;

                // Lock account after 3 failed attempts
                if (member.FailedLoginAttempts >= 3)
                {
                    member.IsLocked = true;
                    member.LockoutEnd = DateTime.UtcNow.AddMinutes(10); // Lock for 10 minutes
                }

                _context.SaveChanges();
                ModelState.AddModelError("Email", "Invalid email or password.");
                return View();
            }

            // Reset failed login attempts on success
            member.FailedLoginAttempts = 0;
            member.IsLocked = false;
            member.LockoutEnd = null;
            await _context.SaveChangesAsync();

            // Secure session setup
            HttpContext.Session.SetString("UserEmail", member.Email);
            HttpContext.Session.SetString("UserId", member.Id.ToString());

            return RedirectToAction("Index", "Home"); // Redirect to homepage
        }

        private async Task<bool> VerifyReCaptcha(string token)
        {
            var secretKey = _configuration["GoogleReCaptcha:SecretKey"]; // Use injected configuration
            var client = new HttpClient();
            var response = await client.PostAsync($"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={token}", null);
            var jsonResponse = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(jsonResponse);
            return doc.RootElement.GetProperty("success").GetBoolean();
        }

        private static bool VerifyPassword(string password, string storedHash)
        {
            byte[] salt = new byte[16];

            byte[] hashBytes = Convert.FromBase64String(storedHash);
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
    }
}

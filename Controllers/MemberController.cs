using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using AceAgencyMembership.Data;
using AceAgencyMembership.Models;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace AceAgencyMembership.Controllers
{
    public class MemberController : Controller
    {
        private readonly ApplicationDbContext _context;

        public MemberController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(Member member, string password, string confirmPassword)
        {
            if (password != confirmPassword)
            {
                ModelState.AddModelError("Password", "Passwords do not match.");
                return View();
            }

            if (_context.Users.Any(m => m.Email == member.Email))
            {
                ModelState.AddModelError("Email", "Email is already registered.");
                return View();
            }

            // Hash Password
            member.PasswordHash = HashPassword(password);

            // Encrypt NRIC
            member.SetNRIC(member.EncryptedNRIC);

            // Initialize other security properties
            member.PasswordLastChanged = DateTime.UtcNow;
            member.MustChangePassword = false;
            member.IsEmailVerified = false;
            member.EmailVerificationToken = GenerateEmailVerificationToken();

            // Save Member
            _context.Members.Add(member);
            await _context.SaveChangesAsync();

            return RedirectToAction("Login");
        }

        private static string HashPassword(string password)
        {
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            return Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 32));
        }

        private string GenerateEmailVerificationToken()
        {
            byte[] tokenBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(tokenBytes);
            }
            return Convert.ToBase64String(tokenBytes);
        }
    }
}

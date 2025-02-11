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

            if (_context.Members.Any(m => m.Email == member.Email))
            {
                ModelState.AddModelError("Email", "Email is already registered.");
                return View();
            }

            // Hash Password
            member.PasswordHash = HashPassword(password);

            // Encrypt NRIC
            member.SetNRIC(member.EncryptedNRIC);

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
    }
}

using AceAgencyMembership.Data;
using AceAgencyMembership.Models;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using System.Net.Mail;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace AceAgencyMembership.Controllers
{
    public class AuthController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthController> _logger; // Add this line

        public AuthController(ApplicationDbContext context, IConfiguration configuration, ILogger<AuthController> logger)
        {
            _context = context;
            _configuration = configuration;
            _logger = logger; // Assign the logger
        }

        [HttpGet]
        public IActionResult Login()
        {
            try
            {
                return View();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while loading the Login view.");
                return HandleError("Login");
            }
        }

        [HttpGet]
        public IActionResult Register()
        {
            try
            {
                return View(); // Ensure this line is present
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while loading the Register view.");
                return HandleError("Register");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return View("Register", model);
                }

                // Check if email is already registered
                if (_context.Members.Any(m => m.Email == model.Email))
                {
                    ModelState.AddModelError("Email", "Email is already registered.");
                    return View("Register", model);
                }

                // Check for strong password
                if (!IsStrongPassword(model.Password))
                {
                    ModelState.AddModelError("Password", "Password must be at least 12 characters long and include uppercase, lowercase, numbers, and special characters.");
                    return View("Register", model);
                }

                // 🛠 Resume Upload Handling
                string resumeFileName = null;

                if (model.ResumeFilePath != null && model.ResumeFilePath.Length > 0)
                {
                    var allowedExtensions = new[] { ".pdf", ".docx" };
                    var extension = Path.GetExtension(model.ResumeFilePath.FileName)?.ToLower();

                    if (string.IsNullOrEmpty(extension) || !allowedExtensions.Contains(extension))
                    {
                        ModelState.AddModelError("ResumeFilePath", "Invalid file type. Only PDF and DOCX are allowed.");
                        return View("Register", model);
                    }

                    if (model.ResumeFilePath.Length > 5 * 1024 * 1024) // 5MB Limit
                    {
                        ModelState.AddModelError("ResumeFilePath", "File size must be less than 5MB.");
                        return View("Register", model);
                    }

                    // Ensure directory exists
                    var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/uploads");
                    if (!Directory.Exists(uploadsFolder))
                    {
                        Directory.CreateDirectory(uploadsFolder);
                    }

                    // Generate unique file name
                    resumeFileName = $"{Guid.NewGuid()}{extension}";
                    var filePath = Path.Combine(uploadsFolder, resumeFileName);

                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await model.ResumeFilePath.CopyToAsync(stream);
                    }
                }

                // Create Member object
                var member = new Member
                {
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    Gender = model.Gender,
                    Email = model.Email,
                    DateOfBirth = model.DateOfBirth,
                    WhoAmI = model.WhoAmI,
                    PasswordHash = HashPassword(model.Password),
                    ResumeFilePath = resumeFileName,
                };

                // Encrypt NRIC using SetNRIC method
                if (!string.IsNullOrEmpty(model.EncryptedNRIC))
                {
                    member.SetNRIC(model.EncryptedNRIC);
                }
                else
                {
                    ModelState.AddModelError("EncryptedNRIC", "NRIC cannot be empty.");
                    return View("Register", model);
                }

                // Add the member to the database
                _context.Members.Add(member);
                await _context.SaveChangesAsync();

                // Redirect to the login page after successful registration
                return RedirectToAction("Login");
            }
            catch (DbUpdateException dbEx)
            {
                _logger.LogError(dbEx, "Database error during registration: {Message}", dbEx.InnerException?.Message);
                ModelState.AddModelError("", $"A database error occurred: {dbEx.InnerException?.Message}");
                return View("Register", model);
            }
            catch (IOException ioEx)
            {
                _logger.LogError(ioEx, "File upload error during registration.");
                ModelState.AddModelError("ResumeFilePath", "Error uploading file. Please try again.");
                return View("Register", model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unexpected error occurred while registering a new member.");
                ModelState.AddModelError("", $"An unexpected error occurred. Details: {ex.Message}");
                return View("Register", model);
            }
        }

        // Helper method for password complexity check

        private bool IsStrongPassword(string password)
        {
            return password.Length >= 12 &&
                   password.Any(char.IsUpper) &&
                   password.Any(char.IsLower) &&
                   password.Any(char.IsDigit) &&
                   password.Any(ch => !char.IsLetterOrDigit(ch));
        }


        private void SendVerificationEmail(string email, string token)
        {
            try
            {
                var verifyUrl = $"https://yourdomain.com/Auth/VerifyEmail?token={token}";
                var smtpClient = new SmtpClient("smtp.gmail.com")
                {
                    Port = 587,
                    Credentials = new NetworkCredential("jedi200614@gmail.com", "your-app-password"),
                    EnableSsl = true,
                };

                smtpClient.Send("your-email@gmail.com", email, "Verify Your Account", $"Click the link to verify: {verifyUrl}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send verification email.");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string recaptchaToken)
        {
            try
            {
                if (string.IsNullOrEmpty(recaptchaToken))
                {
                    ModelState.AddModelError("Recaptcha", "ReCaptcha token is missing.");
                    return HandleError("Login");
                }

                var secretKey = _configuration["GoogleReCaptcha:SecretKey"]; // Read from appsettings.json

                bool isValidCaptcha = await VerifyReCaptcha(recaptchaToken, secretKey);
                if (!isValidCaptcha)
                {
                    ModelState.AddModelError("Recaptcha", "ReCaptcha validation failed.");
                    return HandleError("Login");
                }

                if (!ModelState.IsValid)
                {
                    return View("Login", model);
                }

                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

                // Sanitize Email Input
                model.Email = model.Email.Trim().ToLower();

                var member = await _context.Members.FirstOrDefaultAsync(m => m.Email == model.Email);

                if (member == null)
                {
                    _context.AuditLogs.Add(new AuditLog { Action = "Failed Login", Email = model.Email, IPAddress = ipAddress });
                    await _context.SaveChangesAsync();
                    ModelState.AddModelError("Email", "Invalid email or password.");
                    return HandleError("Login");
                }

                if (member.IsLocked && member.LockoutEnd > DateTime.UtcNow)
                {
                    _context.AuditLogs.Add(new AuditLog { Action = "Account Locked", Email = model.Email, IPAddress = ipAddress });
                    await _context.SaveChangesAsync();
                    ModelState.AddModelError("Email", $"Account locked."); //"Try again after {member.LockoutEnd}."
                    return HandleError("Login");
                }

                if (!VerifyPassword(model.Password, member.PasswordHash))
                {
                    member.FailedLoginAttempts++;

                    if (member.FailedLoginAttempts >= 3)
                    {
                        member.LockAccount(DateTime.UtcNow.AddMinutes(10));
                        _context.AuditLogs.Add(new AuditLog { Action = "Account Locked", Email = model.Email, IPAddress = ipAddress });
                    }
                    else
                    {
                        _context.AuditLogs.Add(new AuditLog { Action = "Failed Login", Email = model.Email, IPAddress = ipAddress });
                    }

                    await _context.SaveChangesAsync();
                    ModelState.AddModelError("Email", "Invalid email or password.");
                    return HandleError("Login");
                }

                // Check if password is expired (90 days policy)
                if (member.PasswordLastChanged.AddDays(90) < DateTime.UtcNow)
                {
                    member.MustChangePassword = true;
                    _context.SaveChanges();
                    return RedirectToAction("ChangePassword");
                }

                // Successful login - Set session variables
                HttpContext.Session.SetString("User Email", member.Email);
                HttpContext.Session.SetString("User Id", member.Id.ToString());

                // Redirect to the landing page after successful login
                return RedirectToAction("Landing");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during login.");
                return HandleError("Login");
            }
        }

        [HttpGet]
        public IActionResult VerifyEmailNotice(string token = null)
        {
            // Hard-code the verification token for testing purposes
            const string hardCodedToken = "your-hardcoded-token"; // Replace with an actual token for a valid user

            // If no token is provided, use the hard-coded token
            if (string.IsNullOrEmpty(token))
            {
                token = hardCodedToken;
            }

            // Attempt to verify the email
            try
            {
                var member = _context.Members.FirstOrDefault(m => m.EmailVerificationToken == token);
                if (member == null)
                {
                    return BadRequest("Invalid verification token.");
                }

                member.IsEmailVerified = true;
                member.EmailVerificationToken = null;
                _context.SaveChanges();

                // Redirect to the login page after successful verification
                return RedirectToAction("Login");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during email verification.");
                return HandleError("Login");
            }
        }

    

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult VerifyEmail(string email)
        {
            try
            {
                if (!string.IsNullOrEmpty(email))
                {
                    // Attempt to send a new verification email
                    var member = _context.Members.FirstOrDefault(m => m.Email == email);
                    if (member != null)
                    {
                        // Generate a new verification token
                        member.EmailVerificationToken = Guid.NewGuid().ToString();
                        _context.SaveChanges();

                        // Send verification email
                        SendVerificationEmail(member.Email, member.EmailVerificationToken);
                    }
                    else
                    {
                        ModelState.AddModelError("Email", "Email address not found.");
                    }
                }
                else
                {
                    ModelState.AddModelError("Email", "Email address cannot be empty.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while processing the verification email.");
                ModelState.AddModelError("", "An error occurred while sending the verification email. Please try again later.");
            }

            ViewData["Title"] = "Email Verification Notice";
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var email = HttpContext.Session.GetString("User Email");
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

                if (string.IsNullOrEmpty(email))
                {
                    ModelState.AddModelError("Email", "Successfully Logged Out.");
                    return HandleError("Login");
                }

                if (!string.IsNullOrEmpty(email))
                {
                    _context.AuditLogs.Add(new AuditLog { Action = "Logout", Email = email, IPAddress = ipAddress });
                    await _context.SaveChangesAsync();
                }

                HttpContext.Session.Clear();
                return RedirectToAction("Login");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during logout.");
                return HandleError("Login");
            }
        }

        [HttpGet]
        public IActionResult Verify2FA()
        {
            try
            {
                return View(new Verify2FAViewModel());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while loading the Verify2FA view.");
                return HandleError("Verify2FA");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Verify2FA(Verify2FAViewModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return View("Verify2FA", model);
                }

                var email = HttpContext.Session.GetString("Pending2FA");
                if (email == null) return RedirectToAction("Login");

                var member = _context.Members.FirstOrDefault(m => m.Email == email);

                if (member == null || member.TwoFactorCode != model.Code || member.TwoFactorExpiry < DateTime.UtcNow)
                {
                    ModelState.AddModelError("OTP", "Invalid or expired OTP.");
                    return HandleError("Verify2FA");
                }

                HttpContext.Session.SetString("User  Email", member.Email);
                HttpContext.Session.SetString("User  Id", member.Id.ToString());

                // Clear OTP after successful verification
                member.TwoFactorCode = null;
                member.TwoFactorExpiry = null;
                await _context.SaveChangesAsync();

                // Successful login logic here...
                return RedirectToAction("Landing"); // Redirect to the Landing page;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during 2FA verification.");
                return HandleError("Verify2FA");
            }
        }

        [HttpGet]
        public IActionResult Landing()
        {
            // Assuming you want to display the logged-in user's information
            var email = HttpContext.Session.GetString("User Email");
            var member = _context.Members.FirstOrDefault(m => m.Email == email);

            if (member == null)
            {
                // Handle the case where the member is not found
                return RedirectToAction("Login");
            }

            // Decrypt sensitive data (e.g., NRIC)
            var decryptedNRIC = member.GetNRIC(); // Decrypt the NRIC

            // Create a view model to pass to the view
            var model = new RegisterViewModel
            {
                FirstName = member.FirstName,
                LastName = member.LastName,
                EncryptedNRIC = decryptedNRIC, // Add decrypted NRIC to the model
                                               // Populate other properties as needed
            };

            return View(model);
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            try
            {
                return View(new ForgotPasswordViewModel());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while loading the ForgotPassword view.");
                return HandleError("ForgotPassword");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ForgotPassword(ForgotPasswordViewModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return View("ForgotPassword", model);
                }

                var member = _context.Members.FirstOrDefault(m => m.Email == model.Email);
                if (member == null)
                {
                    ModelState.AddModelError("Email", "Email not found.");
                    return HandleError("ForgotPassword");
                }

                // Generate a reset token (for simplicity, store a GUID)
                var resetToken = Guid.NewGuid().ToString();
                HttpContext.Session.SetString("PasswordResetToken", resetToken);
                HttpContext.Session.SetString("ResetEmail", model.Email);

                // Simulate sending email
                ViewData["Message"] = $"Use this token: {resetToken} to reset your password.";

                return View();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during the Forgot Password process.");
                return HandleError("ForgotPassword");
            }
        }

        [HttpGet]
        public IActionResult ResetPassword()
        {
            try
            {
                return View(new ResetPasswordViewModel());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while loading the Reset Password view.");
                return HandleError("ResetPassword");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            try
            {
                var storedToken = HttpContext.Session.GetString("PasswordResetToken");
                var storedEmail = HttpContext.Session.GetString("ResetEmail");

                if (storedToken == null || storedEmail == null || model.Token != storedToken || model.Email != storedEmail)
                {
                    ModelState.AddModelError("Token", "Invalid or expired reset token.");
                    return HandleError("ResetPassword");
                }

                var member = _context.Members.FirstOrDefault(m => m.Email == model.Email);
                if (member == null)
                {
                    ModelState.AddModelError("Email", "User  not found.");
                    return HandleError("ResetPassword");
                }

                // Check if the new password was used before
                if (VerifyPassword(model.NewPassword, member.PasswordHash) ||
                    (!string.IsNullOrEmpty(member.PreviousPasswordHash1) && VerifyPassword(model.NewPassword, member.PreviousPasswordHash1)) ||
                    (!string.IsNullOrEmpty(member.PreviousPasswordHash2) && VerifyPassword(model.NewPassword, member.PreviousPasswordHash2)))
                {
                    ModelState.AddModelError("NewPassword", "You cannot reuse your last two passwords.");
                    return HandleError("ResetPassword");
                }

                // Enforce password complexity
                if (!IsStrongPassword(model.NewPassword))
                {
                    ModelState.AddModelError("NewPassword", "Password must be at least 12 characters long and include uppercase, lowercase, numbers, and special characters.");
                    return HandleError("ResetPassword");
                }

                // Update password history
                member.PreviousPasswordHash2 = member.PreviousPasswordHash1;
                member.PreviousPasswordHash1 = member.PasswordHash;
                member.PasswordHash = HashPassword(model.NewPassword);

                _context.SaveChanges();

                // Clear session tokens after reset
                HttpContext.Session.Remove("PasswordResetToken");
                HttpContext.Session.Remove("ResetEmail");

                return RedirectToAction("Login");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during password reset.");
                return HandleError("ResetPassword");
            }
        }

        [HttpGet]
        public IActionResult ChangePassword()
        {
            try
            {
                return View();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while loading the Change Password view.");
                return HandleError("ChangePassword");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            try
            {
                var email = HttpContext.Session.GetString("User  Email"); // Ensure the key matches
                var member = await _context.Members.FirstOrDefaultAsync(m => m.Email == email);

                if (member == null) return RedirectToAction("Login");

                if (!VerifyPassword(model.CurrentPassword, member.PasswordHash))
                {
                    ModelState.AddModelError("CurrentPassword", "Current password is incorrect.");
                    return View(model); // Return the view with the model to show errors
                }

                if (model.NewPassword != model.ConfirmNewPassword)
                {
                    ModelState.AddModelError("NewPassword", "Passwords do not match.");
                    return View(model);
                }

                if (!IsStrongPassword(model.NewPassword))
                {
                    ModelState.AddModelError("NewPassword", "Password must meet complexity requirements.");
                    return View(model);
                }

                // Prevent password reuse
                if (VerifyPassword(model.NewPassword, member.PasswordHash) ||
                    (!string.IsNullOrEmpty(member.PreviousPasswordHash1) && VerifyPassword(model.NewPassword, member.PreviousPasswordHash1)) ||
                    (!string.IsNullOrEmpty(member.PreviousPasswordHash2) && VerifyPassword(model.NewPassword, member.PreviousPasswordHash2)))
                {
                    ModelState.AddModelError("NewPassword", "You cannot reuse your last two passwords.");
                    return View(model);
                }

                // Update password history
                member.PreviousPasswordHash2 = member.PreviousPasswordHash1;
                member.PreviousPasswordHash1 = member.PasswordHash;
                member.PasswordHash = HashPassword(model.NewPassword);
                member.PasswordLastChanged = DateTime.UtcNow;
                member.MustChangePassword = false;

                await _context.SaveChangesAsync();

                return RedirectToAction("Landing");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during password change.");
                return HandleError("ChangePassword");
            }
        }

        private async Task<bool> VerifyReCaptcha(string token, string secretKey)
        {
            if (string.IsNullOrEmpty(token))
            {
                return false; // Prevent empty token requests
            }

            if (string.IsNullOrEmpty(secretKey))
            {
                throw new InvalidOperationException("ReCaptcha Secret Key is missing.");
            }

            using var client = new HttpClient();
            var values = new Dictionary<string, string>
            {
                { "secret", secretKey },
                { "response", token }
            };

            var content = new FormUrlEncodedContent(values);
            var response = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);

            if (!response.IsSuccessStatusCode)
            {
                return false; // Failed to reach Google API
            }

            var jsonResponse = await response.Content.ReadAsStringAsync();

            try
            {
                using var doc = JsonDocument.Parse(jsonResponse);
                return doc.RootElement.TryGetProperty("success", out var success) && success.GetBoolean();
            }
            catch (JsonException)
            {
                return false; // Handle invalid JSON response
            }
        }

        private void SendOtpEmail(string email, string otp)
        {
            var smtpUser = _configuration["Smtp:Username"];
            var smtpPass = _configuration["Smtp:Password"];
            var smtpHost = _configuration["Smtp:Host"];
            var smtpPort = int.Parse(_configuration["Smtp:Port"] ?? "587");

            if (string.IsNullOrEmpty(smtpUser) || string.IsNullOrEmpty(smtpPass))
            {
                throw new InvalidOperationException("SMTP credentials are not configured.");
            }

            using var smtpClient = new SmtpClient(smtpHost)
            {
                Port = smtpPort,
                Credentials = new NetworkCredential(smtpUser, smtpPass),
                EnableSsl = true,
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress(smtpUser),
                Subject = "Your OTP Code",
                Body = $"Your OTP is: {otp}",
                IsBodyHtml = false,
            };

            mailMessage.To.Add(email);

            try
            {
                smtpClient.Send(mailMessage);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send OTP email.");
            }
        }
        private IActionResult HandleError(string currentView)
        {
            var errorViewModel = new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier };
            Console.WriteLine($"Returning error view: {currentView} with RequestId: {errorViewModel.RequestId}");

            return View(currentView);
        }


        private static string HashPassword(string password)
        {
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            byte[] hash = KeyDerivation.Pbkdf2(
                password: password,
 salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 32);

            byte[] hashBytes = new byte[48];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 32);

            return Convert.ToBase64String(hashBytes);
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
            catch (Exception ex)
            {
                // Log the error for debugging
                Console.WriteLine($"Error verifying password: {ex.Message}");
                return false;
            }
        }
    }
}
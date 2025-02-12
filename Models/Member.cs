using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AceAgencyMembership.Models
{
    public class Member : IdentityUser<int>
    {
        [Required, StringLength(50)]
        public string FirstName { get; set; }

        [Required, StringLength(50)]
        public string LastName { get; set; }

        [Required, StringLength(1)]
        public string Gender { get; set; }

        [Required, StringLength(255)]
        public string EncryptedNRIC { get; set; } // Store the encrypted NRIC

        [Required, StringLength(100)]
        [EmailAddress]
        public override string Email { get; set; } // Override Email from IdentityUser

        [Required]
        public DateTime DateOfBirth { get; set; }

        public string ResumeFilePath { get; set; } // File path for uploaded resume

        [Required]
        public string WhoAmI { get; set; } // Allow all special characters

        public int FailedLoginAttempts { get; set; } = 0; // Track failed logins

        public bool IsLocked => LockoutEnd.HasValue && LockoutEnd.Value > DateTime.UtcNow;

        // Store previous passwords to prevent reuse
        public string PreviousPasswordHash1 { get; set; }
        public string PreviousPasswordHash2 { get; set; }

        // Method to lock the user until a specific date
        public void LockAccount(DateTime lockoutEnd)
        {
            LockoutEnd = lockoutEnd;
        }

        public void UnlockAccount()
        {
            LockoutEnd = null;
        }

        // AES Encryption Key (should be stored in a secure config in production)
        private static readonly string EncryptionKey = "YourSecretKey12345"; // Ensure this is 16, 24, or 32 bytes

        // Encrypt NRIC
        public void SetNRIC(string nric)
        {
            EncryptedNRIC = Encrypt(nric);
        }

        // Decrypt NRIC
        public string GetNRIC()
        {
            return Decrypt(EncryptedNRIC);
        }

        private static string Encrypt(string text)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(EncryptionKey);
                aes.IV = new byte[16]; // Default IV (for simplicity)

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(text);
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
                    return Convert.ToBase64String(encryptedBytes);
                }
            }
        }

        private static string Decrypt(string cipherText)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(EncryptionKey);
                aes.IV = new byte[16]; // Default IV (for simplicity)

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    byte[] encryptedBytes = Convert.FromBase64String(cipherText);
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }
    }
}

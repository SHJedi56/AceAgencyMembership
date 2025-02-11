using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;

namespace AceAgencyMembership.Models
{
    public class Member
    {
        [Key]
        public int Id { get; set; }

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
        public string Email { get; set; }

        [Required]
        public string PasswordHash { get; set; } // Hashed Password

        [Required]
        public DateTime DateOfBirth { get; set; }

        public string ResumeFilePath { get; set; } // File path for uploaded resume

        [Required]
        public string WhoAmI { get; set; } // Allow all special characters

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
    
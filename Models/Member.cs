using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;

namespace AceAgencyMembership.Models
{
    public class Member : IdentityUser<int>
    {
        [Required, StringLength(50)]
        public string? FirstName { get; set; }

        [Required, StringLength(50)]
        public string? LastName { get; set; }

        [Required, StringLength(1)]
        public string? Gender { get; set; }

        [Required, StringLength(255)]
        public string? EncryptedNRIC { get; set; }

        [Required, StringLength(100)]
        [EmailAddress]
        public override string? Email { get; set; }

        [Required]
        public DateTime DateOfBirth { get; set; }

        public string? ResumeFilePath { get; set; }

        [Required]
        public string? WhoAmI { get; set; }

        public int FailedLoginAttempts { get; set; } = 0;

        public bool IsLocked => LockoutEnd.HasValue && LockoutEnd.Value > DateTime.UtcNow;

        public string? PreviousPasswordHash1 { get; set; }
        public string? PreviousPasswordHash2 { get; set; }

        // Missing properties added to fix errors
        public DateTime PasswordLastChanged { get; set; } = DateTime.UtcNow;
        public bool MustChangePassword { get; set; } = false;
        public bool IsEmailVerified { get; set; } = false;
        public string? EmailVerificationToken { get; set; }
        public string? TwoFactorCode { get; set; }
        public DateTime? TwoFactorExpiry { get; set; }

        public void LockAccount(DateTime lockoutEnd)
        {
            LockoutEnd = lockoutEnd;
        }

        public void UnlockAccount()
        {
            LockoutEnd = null;
        }

        private static readonly string EncryptionKey = "YourSecretKey12345";  // Ensure this is a secure key, ideally from a secure location

        // Set NRIC (Encrypt)
        public void SetNRIC(string nric)
        {
            EncryptedNRIC = Encrypt(nric);
        }

        // Get NRIC (Decrypt)
        public string? GetNRIC()
        {
            return Decrypt(EncryptedNRIC);
        }

        // AES encryption method
        private static string Encrypt(string text)
        {
            using (Aes aes = Aes.Create())
            {
                // Derive a 256-bit key using SHA256
                aes.Key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(EncryptionKey));

                // Use a random IV for each encryption (better security practice)
                aes.GenerateIV();

                // Encrypt the text
                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(text);
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);

                    // Combine the IV and encrypted data to store it together
                    byte[] result = new byte[aes.IV.Length + encryptedBytes.Length];
                    Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
                    Array.Copy(encryptedBytes, 0, result, aes.IV.Length, encryptedBytes.Length);

                    return Convert.ToBase64String(result);
                }
            }
        }

        // AES decryption method
        private static string? Decrypt(string cipherText)
        {
            byte[] cipherBytes = Convert.FromBase64String(cipherText);

            using (Aes aes = Aes.Create())
            {
                // Derive the key from the same EncryptionKey using SHA256
                aes.Key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(EncryptionKey));

                // Extract the IV from the stored data (first 16 bytes)
                byte[] iv = new byte[16];
                Array.Copy(cipherBytes, 0, iv, 0, iv.Length);

                // Extract the encrypted data (remaining bytes)
                byte[] encryptedBytes = new byte[cipherBytes.Length - iv.Length];
                Array.Copy(cipherBytes, iv.Length, encryptedBytes, 0, encryptedBytes.Length);

                // Decrypt the data
                using (var decryptor = aes.CreateDecryptor(aes.Key, iv))
                {
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }
    }
}

using System;
using System.ComponentModel.DataAnnotations;

namespace AceAgencyMembership.Models
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string Action { get; set; } // Login, Logout, Failed Login, Account Lock

        [Required]
        public string Email { get; set; } // Store user email

        [Required]
        public DateTime Timestamp { get; set; } = DateTime.UtcNow; // Log time in UTC

        public string IPAddress { get; set; } // Track user IP
    }
}

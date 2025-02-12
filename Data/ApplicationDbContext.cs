using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using AceAgencyMembership.Models;

namespace AceAgencyMembership.Data
{
    // Inherit from IdentityDbContext to support Identity
    public class ApplicationDbContext : IdentityDbContext<IdentityUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        // Register database tables (DbSets)
        public DbSet<Member> Members { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder); // Call base method for Identity setup

            // Ensure unique emails for Members
            modelBuilder.Entity<Member>()
                .HasIndex(m => m.Email)
                .IsUnique();

            // Index AuditLog Timestamp for faster queries
            modelBuilder.Entity<AuditLog>()
                .HasIndex(a => a.Timestamp);
        }
    }
}

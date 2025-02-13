using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AceAgencyMembership.Migrations
{
    /// <inheritdoc />
    public partial class FinalSecurityUpdates : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "EmailVerificationToken",
                table: "Members",
                type: "longtext",
                nullable: false)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<bool>(
                name: "IsEmailVerified",
                table: "Members",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "MustChangePassword",
                table: "Members",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTime>(
                name: "PasswordLastChanged",
                table: "Members",
                type: "datetime(6)",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<string>(
                name: "PreviousPasswordHash1",
                table: "Members",
                type: "longtext",
                nullable: false)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "PreviousPasswordHash2",
                table: "Members",
                type: "longtext",
                nullable: false)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "TwoFactorCode",
                table: "Members",
                type: "longtext",
                nullable: false)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<DateTime>(
                name: "TwoFactorExpiry",
                table: "Members",
                type: "datetime(6)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EmailVerificationToken",
                table: "Members");

            migrationBuilder.DropColumn(
                name: "IsEmailVerified",
                table: "Members");

            migrationBuilder.DropColumn(
                name: "MustChangePassword",
                table: "Members");

            migrationBuilder.DropColumn(
                name: "PasswordLastChanged",
                table: "Members");

            migrationBuilder.DropColumn(
                name: "PreviousPasswordHash1",
                table: "Members");

            migrationBuilder.DropColumn(
                name: "PreviousPasswordHash2",
                table: "Members");

            migrationBuilder.DropColumn(
                name: "TwoFactorCode",
                table: "Members");

            migrationBuilder.DropColumn(
                name: "TwoFactorExpiry",
                table: "Members");
        }
    }
}

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace backend.Data.Models;

public partial class ApplicationUser : IdentityUser
{
    // public string? FirstName { get; set; }
    // public string? LastName { get; set; }
    // public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    // public DateTime? UpdatedAt { get; set; }
}

public class ApplicationUserConfiguration : IEntityTypeConfiguration<ApplicationUser>
{
    public void Configure(EntityTypeBuilder<ApplicationUser> builder)
    {
        // builder.Property(x => x.FirstName)
        //     .HasMaxLength(100);
        // 
        // builder.Property(x => x.CreatedAt)
        //     .IsRequired();

        // Configure relationships if needed
        // Example:
        // builder.HasMany<Todo>()
        //     .WithOne(x => x.User)
        //     .HasForeignKey(x => x.UserId)
        //     .OnDelete(DeleteBehavior.Cascade);
    }
}


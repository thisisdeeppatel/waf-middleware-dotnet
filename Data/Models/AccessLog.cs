using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace backend.Data.Models;

public class AccessLog
{
    public long Id { get; set; }

    public string? Ip { get; set; }

    public string UserAgent { get; set; } = "";

    public string Path { get; set; } = "";

    public int RiskScore { get; set; }

    /// <summary>JSON array of scoring factor strings.</summary>
    public string Factors { get; set; } = "";

    public string SignatureHash { get; set; } = "";

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}

public class AccessLogConfiguration : IEntityTypeConfiguration<AccessLog>
{
    public void Configure(EntityTypeBuilder<AccessLog> builder)
    {
        builder.ToTable("AccessLogs");

        builder.HasKey(x => x.Id);

        builder.Property(x => x.Ip)
            .HasMaxLength(64);

        builder.Property(x => x.UserAgent)
            .HasMaxLength(2048);

        builder.Property(x => x.Path)
            .HasMaxLength(2048);

        builder.Property(x => x.Factors)
            .HasColumnType("text");

        builder.Property(x => x.SignatureHash)
            .HasMaxLength(64)
            .IsRequired();

        builder.Property(x => x.CreatedAt)
            .IsRequired();

        builder.Property(x => x.UpdatedAt)
            .IsRequired();
    }
}

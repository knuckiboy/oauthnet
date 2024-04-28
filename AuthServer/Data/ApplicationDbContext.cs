using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Data
{
    public class ApplicationDbContext : DbContext
    {
        public virtual DbSet<TokenMap> TokenMaps { get; set; }
        public ApplicationDbContext(DbContextOptions options)
        : base(options)
        {
        }
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.EnableSensitiveDataLogging();
        }
    }
}

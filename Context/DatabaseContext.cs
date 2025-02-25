using GetThingsDone.Models;
using Microsoft.EntityFrameworkCore;

namespace GetThingsDone.Context {

    public class DatabaseContext : DbContext {
        
        public DatabaseContext(DbContextOptions<DatabaseContext> options) : base(options) {}

        public DbSet<UserModel> Users { get; set; }

    }

}
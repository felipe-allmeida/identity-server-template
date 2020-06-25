using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace IdentityServer.Infra.Data.Identity
{
    public class ConfigurationDbContextFactory : IDesignTimeDbContextFactory<ConfigurationDbContext>
    {
        public ConfigurationDbContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<ConfigurationDbContext>();
            optionsBuilder.UseSqlServer("Server=(localdb)\\mssqllocaldb;Database=AuthServer;Trusted_Connection=True;MultipleActiveResultSets=true",
                sql => sql.MigrationsAssembly(typeof(ConfigurationDbContextFactory).GetTypeInfo().Assembly.GetName().Name));
            return new ConfigurationDbContext(optionsBuilder.Options, new ConfigurationStoreOptions());
        }
    }
}

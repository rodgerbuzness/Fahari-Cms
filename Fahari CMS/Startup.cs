using DataService;
using FunctionalService;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SpaServices.AngularCli;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelService;
using System;

namespace Fahari_CMS
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            // In production, the Angular files will be served from this directory
            services.AddSpaStaticFiles(configuration =>
            {
                configuration.RootPath = "ClientApp/dist";
            });

            // Db Connection Options
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlServer(Configuration.GetConnectionString("DbConnection"), x => x.MigrationsAssembly("Fahari CMS"));
            });

            services.AddDbContext<DataProtectionKeysContext>(options =>
            {
                options.UseSqlServer(Configuration.GetConnectionString("DbProtectionConnection"), x => x.MigrationsAssembly("Fahari CMS"));
            });

            // Functional Service
            services.AddTransient<IFunctionalSvc, FunctionalSvc>();
            services.Configure<AdminUserOptions>(Configuration.GetSection("AdminUserOptions"));
            services.Configure<AppUserOptions>(Configuration.GetSection("AppUserOptions"));

            var identityDefaultOptionsConfiguration = Configuration.GetSection("IdentityDefaultOptions");
            services.Configure<IdentityDefaultOptions>(identityDefaultOptionsConfiguration);

            var identityDefaultOtions = identityDefaultOptionsConfiguration.Get<IdentityDefaultOptions>();

            services.AddIdentity<ApplicationUser, IdentityRole>(options => {

                // Password Settings
                options.Password.RequireDigit = identityDefaultOtions.PasswordRequireDigit;
                options.Password.RequiredLength = identityDefaultOtions.PasswordRequiredLength;
                options.Password.RequireNonAlphanumeric = identityDefaultOtions.PasswordRequireNonAlphanumeric;
                options.Password.RequireUppercase = identityDefaultOtions.PasswordRequireUppercase;
                options.Password.RequireLowercase = identityDefaultOtions.PasswordRequireLowercase;
                options.Password.RequiredUniqueChars = identityDefaultOtions.PasswordRequiredUniqueChars;

                // Lockout Settings
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(identityDefaultOtions.LockoutDefaultLockoutTimeSpaninMinutes);
                options.Lockout.MaxFailedAccessAttempts = identityDefaultOtions.LockoutMaxFailedAccessAttempts;

                // User Settings
                options.User.RequireUniqueEmail = identityDefaultOtions.UserRequireUniqueEmail;

                // Email Confirmation require
                options.SignIn.RequireConfirmedEmail = identityDefaultOtions.SignInRequireConfirmedEmail;

            }).AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

             services.AddMvc().AddControllersAsServices().AddRazorRuntimeCompilation().SetCompatibilityVersion(CompatibilityVersion.Version_3_0);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            if (!env.IsDevelopment())
            {
                app.UseSpaStaticFiles();
            }

            app.UseRouting();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "areas",
                    pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}");

                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller}/{action=Index}/{id?}");
            });

            app.UseSpa(spa =>
            {
                // To learn more about options for serving an Angular SPA from ASP.NET Core,
                // see https://go.microsoft.com/fwlink/?linkid=864501

                spa.Options.SourcePath = "ClientApp";

                if (env.IsDevelopment())
                {
                    spa.UseAngularCliServer(npmScript: "start");
                }
            });
        }
    }
}

using OpenID_MVC.OpenIDHelper;

namespace OpenID_MVC
{
    public class Startup
    {
        public static class Settings
        {
            public static IConfiguration Configuration;
        }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            Settings.Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // OPenID connect
            OpenIDAuthentication auth = new();
            auth.AddServices(services);
            //
            services.AddControllersWithViews();

            /*
             * Non policy based authentication
             * Uncomment below and comment the policy section
             */

            //services.AddAuthorization();

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
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.

                //Enable https only for http service behind a load balancer
                //Disable for local testing on http only
                app.Use((context, next) =>
                {
                    context.Request.Scheme = "https";
                    return next();
                });

                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            //Uses the defined policies and customizations from configure services
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}

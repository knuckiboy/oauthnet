using AuthServer;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.LoginPath = "/account/login";
        });
builder.Services.AddDbContext<DbContext>(options =>
{
    // Configure the context to use an in-memory store.
    options.UseInMemoryDatabase(nameof(DbContext));
    // Register the entity sets needed by OpenIddict.
    options.UseOpenIddict();
});
/*builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    // Configure the Entity Framework Core to use Microsoft SQL Server.
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));

    // Register the entity sets needed by OpenIddict.
    options.UseOpenIddict();
});*/

var logger = new LoggerConfiguration()
.MinimumLevel.Debug()
.WriteTo.File("logs/log-.txt", rollingInterval: RollingInterval.Day)
.CreateLogger();
builder.Logging.ClearProviders();
builder.Logging.AddSerilog(logger);

builder.Services.AddOpenIddict()

        // Register the OpenIddict core components.
        .AddCore(options =>
        {
            // Configure OpenIddict to use the EF Core stores/models.
            options.UseEntityFrameworkCore()
                .UseDbContext<DbContext>();
        })

        //Use ApplicationDbContext
        /*.AddCore(options =>
        {
            // Configure OpenIddict to use the EF Core stores/models.
            options.UseEntityFrameworkCore()
                .UseDbContext<ApplicationDbContext>();
        })*/
        // Register the OpenIddict server components.
        .AddServer(options =>
        {
            options
                .AllowClientCredentialsFlow();
            options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();


            options
            .SetAuthorizationEndpointUris("/connect/authorize")
                .SetTokenEndpointUris("/connect/token");

            // Encryption and signing of tokens
            options
                .AddEphemeralEncryptionKey()
                .AddEphemeralSigningKey();

            // Register scopes (permissions)
            options.RegisterScopes("api");

            // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
            options
                .UseAspNetCore()
                .EnableTokenEndpointPassthrough()
            .EnableAuthorizationEndpointPassthrough();
            options
                .AddEphemeralEncryptionKey()
                .AddEphemeralSigningKey()
                .DisableAccessTokenEncryption();
        });

builder.Services.AddHostedService<TestData>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

if (app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.UseAuthentication();



//app.MapRazorPages();
//app.MapDefaultControllerRoute();

app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute();
});

/*app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");*/

app.Run();

using AuthServer;
using AuthServer.Data;
using AuthServer.Entities;
using AuthServer.Handlers;
using AuthServer.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Serilog;

var builder = WebApplication.CreateBuilder(args);
// Configuration Setup
var configuration = builder.Configuration;

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.LoginPath = "/account/login";
        });
//builder.Services.AddDbContext<DbContext>(options =>
//{
//    // Configure the context to use an in-memory store.
//    options.UseInMemoryDatabase(nameof(DbContext));
//    // Register the entity sets needed by OpenIddict.
//    options.UseOpenIddict();
//});
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    if (configuration.GetValue<bool>("UseInMemoryDatabase"))
    {
        // Configure the context to use an in-memory store.
        options.UseInMemoryDatabase(nameof(DbContext));
    }
    else
    {
        // Configure the Entity Framework Core to use Microsoft SQL Server.
        options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    }
    // Register the entity sets needed by OpenIddict.
    options.UseOpenIddict<CustomApplication, CustomAuthorization, CustomScope, CustomToken, Guid>();
});

builder.Services.AddScoped<TestTokenService>();

//Logging Configuration
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
                .UseDbContext<ApplicationDbContext>()
                .ReplaceDefaultEntities<CustomApplication, CustomAuthorization, CustomScope, CustomToken, Guid>();

        })

        .AddValidation(options =>
        {
            options.UseLocalServer();
            // Register the ASP.NET Core host.
            options.UseAspNetCore();

            options.AddEventHandler(TestTokenValidationHandler.ValidateTokenDescriptor);
        })

        //Use ApplicationDbContext
        .AddServer(options =>
        {
            options
                .AllowClientCredentialsFlow();
            options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();
            options.SetAccessTokenLifetime(TimeSpan.FromMinutes(configuration.GetSection("TokenExpiration").Get<int>()));

            options
            .SetAuthorizationEndpointUris(configuration.GetSection("OpenIddict:AuthorizationEndpointUrls").Get<string[]>())
                .SetTokenEndpointUris(configuration.GetSection("OpenIddict:TokenEndpointUrls").Get<string[]>())
                 .SetUserinfoEndpointUris(configuration.GetSection("OpenIddict:UserInfoEndpointUrls").Get<string[]>());

            // Encryption and signing of tokens
            options
                .AddEphemeralEncryptionKey()
                .AddEphemeralSigningKey();

            // Register scopes (permissions)
            options.RegisterScopes("api", "openid");

            // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
            options
                .UseAspNetCore()
                .EnableTokenEndpointPassthrough()
                .EnableUserinfoEndpointPassthrough()
            .EnableAuthorizationEndpointPassthrough();
            options
                .AddEphemeralEncryptionKey()
                .AddEphemeralSigningKey()
                .DisableAccessTokenEncryption();
            // custom handlers
            options.AddEventHandler(TestTokenHandler.ProcessGenTokenDescriptor);
            options.AddEventHandler(TestTokenHandler.CustomTokenServerValidationDescriptor);

            // Production Configuration
            if (configuration.GetSection("OpenIddict:DisableTS").Get<bool>())
            {
                options.UseAspNetCore()
                .DisableTransportSecurityRequirement();
            }
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

// Production Configuration
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseHttpsRedirection();
}

app.UseStaticFiles();

app.UseRouting();

app.UseCors(builder => builder
      .AllowAnyOrigin()
      .AllowAnyHeader()
      .AllowAnyMethod());

app.UseAuthentication();
app.UseAuthorization();



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

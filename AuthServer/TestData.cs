using AuthServer.Data;
using AuthServer.Entities;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using System.Text.Json;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer
{
    public class TestData : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IConfiguration _configuration;

        public TestData(IServiceProvider serviceProvider, IConfiguration configuration)
        {
            _serviceProvider = serviceProvider;
            _configuration = configuration;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();

            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync(cancellationToken);

            //var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var manager = scope.ServiceProvider.GetRequiredService<OpenIddictApplicationManager<CustomApplication>>();

            if (await manager.FindByClientIdAsync("postman1", cancellationToken) is null)
            {
                //await manager.CreateAsync(new OpenIddictApplicationDescriptor
                //{
                //    ApplicationType = ApplicationTypes.Web,
                //    ClientId = "postman1",
                //    ClientSecret = "postman1-secret",
                //    DisplayName = "Postman",
                //    RedirectUris = { new Uri("https://oauth.pstmn.io/v1/callback") },
                //    Permissions =
                //{
                //    OpenIddictConstants.Permissions.Endpoints.Authorization,
                //    OpenIddictConstants.Permissions.Endpoints.Token,

                //    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                //    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,

                //    OpenIddictConstants.Permissions.Prefixes.Scope + "api",

                //    OpenIddictConstants.Permissions.ResponseTypes.Code
                //},
                //Requirements =
                //{
                //    Requirements.Features.ProofKeyForCodeExchange
                //}
                //}, cancellationToken);

                var redirectUrls = _configuration.GetSection("OpenIddict:RedirectUris").Get<string[]>();
                var logoutUrls = _configuration.GetSection("OpenIddict:PostLogoutUris").Get<string[]>();

                await manager.CreateAsync(new CustomApplication
                {
                    ClientId = "postman1",
                    DisplayName = "Postman",
                    RedirectUris = JsonSerializer.Serialize(redirectUrls.Select(x => new Uri(x)).ToHashSet()),
                    Permissions = JsonSerializer.Serialize(new HashSet<string>
                    {
                            OpenIddictConstants.Permissions.Endpoints.Authorization,
                            OpenIddictConstants.Permissions.Endpoints.Token,
                            OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                            OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                            OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                            OpenIddictConstants.Permissions.Endpoints.Introspection,
                            OpenIddictConstants.Permissions.Endpoints.Logout,
                            OpenIddictConstants.Permissions.Prefixes.Scope + "api",
                            OpenIddictConstants.Permissions.ResponseTypes.Code
                    }),
                    PostLogoutRedirectUris = JsonSerializer.Serialize(logoutUrls.Select(x => new Uri(x)).ToHashSet()),
                    CustomApp = "Custom Text",
                    Requirements = JsonSerializer.Serialize(new HashSet<string> { Requirements.Features.ProofKeyForCodeExchange })
                }, "postman1-secret", cancellationToken);


            }


        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}

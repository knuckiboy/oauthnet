using AuthServer.Entities;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

namespace AuthServer.Handlers
{
    public static class TestTokenHandler
    {
        public static OpenIddictServerHandlerDescriptor ProcessTokenDescriptor { get; } = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleTokenRequestContext>().SetType(OpenIddictServerHandlerType.BuiltIn).UseScopedHandler<ProcessToken>().Build();
        public static OpenIddictServerHandlerDescriptor ProcessAuthDescriptor { get; } = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>().UseScopedHandler<ProcessAuth>().SetType(OpenIddictServerHandlerType.BuiltIn).Build();

        public static OpenIddictServerHandlerDescriptor GenTokenDescriptor { get; }
              = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                  .AddFilter<RequireDegradedModeDisabled>()
                  .AddFilter<RequireTokenStorageEnabled>()
                  .AddFilter<RequireTokenEntryCreated>()
                  .UseScopedHandler<CustomCreateTokenEntry>()
                  .SetOrder(AttachSecurityCredentials.Descriptor.Order + 1_000)
                  .SetType(OpenIddictServerHandlerType.Custom)
                  .Build();

        public class ProcessToken : IOpenIddictServerHandler<HandleTokenRequestContext>
        {
            public ValueTask HandleAsync(HandleTokenRequestContext context)
            {
                var principal = context.Principal;
                var transaction = context.Transaction;
                return default;
            }
        }


        public class ProcessAuth : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {

            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                context.Logger.LogInformation(context.ToString());
                return default;
            }
        }

        public class CustomCreateTokenEntry : IOpenIddictServerHandler<GenerateTokenContext>
        {

            private readonly OpenIddictApplicationManager<CustomApplication> _applicationManager;
            private readonly OpenIddictTokenManager<CustomToken> _tokenManager;
            private readonly OpenIddictAuthorizationManager<CustomAuthorization> _authorizeManager;

            public CustomCreateTokenEntry(OpenIddictApplicationManager<CustomApplication> applicationManager, OpenIddictTokenManager<CustomToken> tokenManager, OpenIddictAuthorizationManager<CustomAuthorization> authorizeManager)
            {
                _applicationManager = applicationManager ?? throw new ArgumentException(nameof(OpenIddictApplicationManager<CustomApplication>));
                _tokenManager = tokenManager ?? throw new ArgumentException(nameof(OpenIddictTokenManager<CustomToken>));
                _authorizeManager = authorizeManager ?? throw new ArgumentException(nameof(OpenIddictAuthorizationManager<CustomAuthorization>));
            }

            public async ValueTask HandleAsync(GenerateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }
                if (!context.IsRequestSkipped && !context.IsRequestHandled && !context.IsRejected)
                {

                    var descriptor = new OpenIddictTokenDescriptor
                    {
                        AuthorizationId = context.Principal.GetAuthorizationId(),
                        CreationDate = context.Principal.GetCreationDate(),
                        ExpirationDate = context.Principal.GetExpirationDate(),
                        Principal = context.Principal,
                        Type = context.TokenType
                    };

                    descriptor.Status = context.TokenType switch
                    {
                        // When initially created, device codes are marked as inactive. When the user
                        // approves the authorization demand, the UpdateReferenceDeviceCodeEntry handler
                        // changes the status to "active" and attaches a new payload with the claims
                        // corresponding the user, which allows the client to redeem the device code.
                        TokenTypeHints.DeviceCode => Statuses.Inactive,

                        // For all other tokens, "valid" is the default status.
                        _ => Statuses.Valid
                    };

                    descriptor.Subject = context.TokenType switch
                    {
                        // Device and user codes are not bound to a user, until authorization is granted.
                        TokenTypeHints.DeviceCode or TokenTypeHints.UserCode => null,

                        // For all other tokens, the subject is resolved from the principal.
                        _ => context.Principal.GetClaim(Claims.Subject)
                    };

                    if (!string.IsNullOrEmpty(context.ClientId))
                    {
                        var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ?? throw new Exception("No client found");

                        descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
                    }

                    var customToken = new CustomToken();
                    await _tokenManager.PopulateAsync(customToken, descriptor, context.CancellationToken);
                    customToken.CustomMessage = "CustomText";
                    await _tokenManager.CreateAsync(customToken);
                    var identifier = await _tokenManager.GetIdAsync(customToken);
                    // Attach the token identifier to the principal so that it can be stored in the token payload.
                    context.Principal.SetTokenId(identifier);

                    context.Logger.LogTrace(nameof(CustomCreateTokenEntry), context.TokenType, identifier);
                }

            }
        }
    }
}

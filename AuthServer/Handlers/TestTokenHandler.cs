using AuthServer.Entities;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.Server;
using System.Diagnostics;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using static OpenIddict.Server.OpenIddictServerHandlers;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

namespace AuthServer.Handlers
{
    public static class TestTokenHandler
    {
        public static OpenIddictServerHandlerDescriptor ProcessGenTokenDescriptor { get; } = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>().UseScopedHandler<CustomGenerateAuthToken>().SetOrder(AttachSignInParameters.Descriptor.Order + 1_000).SetType(OpenIddictServerHandlerType.Custom).Build();

        public static OpenIddictServerHandlerDescriptor GenTokenDescriptor { get; }
              = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                  .AddFilter<RequireDegradedModeDisabled>()
                  .AddFilter<RequireTokenStorageEnabled>()
                  .AddFilter<RequireTokenEntryCreated>()
                  .UseScopedHandler<CustomCreateTokenEntry>()
                  .SetOrder(AttachSecurityCredentials.Descriptor.Order + 1_000)
                  .SetType(OpenIddictServerHandlerType.Custom)
                  .Build();

        #region Custom Fields in CustomToken
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
        #endregion
        #region Generate Custom Token and Store Access,Id token in Token table
        public class CustomGenerateAuthToken : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictTokenManager _openIddictTokenManager;

            public CustomGenerateAuthToken(IOpenIddictTokenManager openIddictTokenManager)
            {
                _openIddictTokenManager = openIddictTokenManager;
            }

            public async ValueTask HandleAsync(ProcessSignInContext context)
            {
                string accessTokenId = string.Empty;
                if (context == null)
                {
                    throw new ArgumentNullException("No context");
                }
                if (context.IsRejected || context.IsRequestHandled || context.IsRequestSkipped)
                {
                    throw new InvalidOperationException("Proccess not covered");
                }

                if (context.IncludeAccessToken)
                {
                    Debug.Assert(context.AccessTokenPrincipal is { Identity: ClaimsIdentity }, "no Identity claims");

                    // Extract identifier and store the token there
                    var identifier = context.AccessTokenPrincipal.GetTokenId();
                    accessTokenId = identifier;
                    if (string.IsNullOrEmpty(identifier))
                    {
                        throw new InvalidOperationException("Identifier not found");
                    }
                    var token = await _openIddictTokenManager.FindByIdAsync(identifier, context.CancellationToken);
                    if (token is CustomToken customToken)
                    {
                        customToken.Token = context.AccessToken;
                        await _openIddictTokenManager.UpdateAsync(customToken, context.CancellationToken);
                    }
                }
                if (context.IncludeIdentityToken)
                {
                    Debug.Assert(context.IdentityTokenPrincipal is { Identity: ClaimsIdentity }, "no Identity claims");

                    // Extract identifier and store the token there
                    var identifier = context.IdentityTokenPrincipal.GetTokenId();
                    if (string.IsNullOrEmpty(identifier))
                    {
                        throw new InvalidOperationException("Identifier not found");
                    }
                    var token = await _openIddictTokenManager.FindByIdAsync(identifier, context.CancellationToken);
                    if (token is CustomToken customToken)
                    {
                        customToken.Token = context.IdentityToken;
                        await _openIddictTokenManager.UpdateAsync(customToken, context.CancellationToken);
                    }
                }
                //Todo: split to multiple event handlers and chain
                if (context.IncludeAccessToken || context.IncludeIdentityToken)
                {
                    var customTokenResponse = new CustomOpenIddictResponse(context.Transaction.Response, accessTokenId!);
                    customTokenResponse.AccessToken = accessTokenId;
                    customTokenResponse.IdToken = null;
                    // Todo: generate your custom token
                    context.Transaction.Response = customTokenResponse;
                }

                context.Logger.LogTrace(nameof(CustomGenerateAuthToken));
            }
        }
        #endregion
        public class CustomOpenIddictResponse : OpenIddictResponse
        {
            public string CustomToken
            {
                get { return (string)GetParameter("custom_token"); }
                set { SetParameter("custom_token", value); }
            }

            public CustomOpenIddictResponse(OpenIddictResponse response, string customToken)
            {
                AccessToken = response.AccessToken;
                IdToken = response.IdToken;
                ExpiresIn = response.ExpiresIn;
                TokenType = response.TokenType;
                RefreshToken = response.RefreshToken;
                Iss = response.Iss;
                DeviceCode = response.DeviceCode;
                State = response.State;
                UserCode = response.UserCode;
                VerificationUriComplete = response.VerificationUriComplete;
                ErrorUri = response.ErrorUri;
                CustomToken = customToken;
            }

        }
    }
}

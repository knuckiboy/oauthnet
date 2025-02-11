﻿using AuthServer.Entities;
using AuthServer.Services;
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
        public static OpenIddictServerHandlerDescriptor CustomTokenServerValidationDescriptor { get; } = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>().UseScopedHandler<ServerValidateCustomJsonWebToken>().SetOrder(ResolveTokenValidationParameters.Descriptor.Order - 500).SetType(OpenIddictServerHandlerType.Custom).Build();

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

            public CustomCreateTokenEntry(OpenIddictApplicationManager<CustomApplication> applicationManager, OpenIddictTokenManager<CustomToken> tokenManager)
            {
                _applicationManager = applicationManager ?? throw new ArgumentException(nameof(OpenIddictApplicationManager<CustomApplication>));
                _tokenManager = tokenManager ?? throw new ArgumentException(nameof(OpenIddictTokenManager<CustomToken>));
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
            private readonly IOpenIddictAuthorizationManager _openIddictAuthorizationManager;
            private readonly TestTokenService _testTokenService;

            public CustomGenerateAuthToken(IOpenIddictTokenManager openIddictTokenManager, TestTokenService testTokenService, IOpenIddictAuthorizationManager openIddictAuthorizationManager)
            {
                _openIddictTokenManager = openIddictTokenManager;
                _testTokenService = testTokenService;
                _openIddictAuthorizationManager = openIddictAuthorizationManager;
            }

            public async ValueTask HandleAsync(ProcessSignInContext context)
            {
                CustomToken accessToken = null;
                CustomToken idToken = null;
                CustomToken refreshToken = null;
                CustomAuthorization customAuthorization = null;
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
                    if (string.IsNullOrEmpty(identifier))
                    {
                        throw new InvalidOperationException("Identifier not found");
                    }
                    var token = await _openIddictTokenManager.FindByIdAsync(identifier, context.CancellationToken);
                    if (token is CustomToken customToken)
                    {
                        customToken.Token = context.AccessToken;
                        accessToken = customToken;
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
                        idToken = customToken;
                        await _openIddictTokenManager.UpdateAsync(customToken, context.CancellationToken);
                    }
                }

                if (context.IncludeRefreshToken)
                {
                    Debug.Assert(context.RefreshTokenPrincipal is { Identity: ClaimsIdentity }, "no Identity claims");

                    // Extract identifier and store the token there
                    var identifier = context.RefreshTokenPrincipal.GetTokenId();
                    if (string.IsNullOrEmpty(identifier))
                    {
                        throw new InvalidOperationException("Identifier not found");
                    }
                    var token = await _openIddictTokenManager.FindByIdAsync(identifier, context.CancellationToken);
                    if (token is CustomToken customToken)
                    {
                        customToken.Token = context.RefreshToken;
                        refreshToken = customToken;
                        await _openIddictTokenManager.UpdateAsync(customToken, context.CancellationToken);
                    }
                }

                var identity = context.Principal.Identity as ClaimsIdentity;
                var authId = identity?.GetAuthorizationId();
                if (identity != null && authId != null)
                {
                    var authorization = await _openIddictAuthorizationManager.FindByIdAsync(authId, context.CancellationToken);
                    if (authorization is CustomAuthorization cA)
                    {
                        customAuthorization = cA;
                    }
                }

                //Todo: split to multiple event handlers and chain
                if (accessToken != null)
                {
                    try
                    {
                        var identifier = identity.GetClaim(Claims.Subject);
                        // Todo: generate your custom token
                        var tokenMap = await _testTokenService.GenerateToken(identifier, accessToken, idToken, refreshToken, customAuthorization);

                        context.Transaction.Response.AccessToken = tokenMap.Token;
                        context.Transaction.Response.IdToken = null;
                        context.Transaction.Response.RefreshToken = null;
                    }
                    catch (Exception ex)
                    {
                        context.Logger.LogError(ex.ToString());
                        context.Reject(
                       error: Errors.InvalidRequest, ex.Message);

                        return;
                    }
                }

                context.Logger.LogTrace(nameof(CustomGenerateAuthToken));
            }
        }
        #endregion

        #region Server Validation
        public class ServerValidateCustomJsonWebToken : IOpenIddictServerHandler<ValidateTokenContext>
        {
            private readonly TestTokenService _testTokenService;

            public ServerValidateCustomJsonWebToken(TestTokenService testTokenService)
            {
                _testTokenService = testTokenService;
            }

            public ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException("no context");
                }
                if (context.IsRequestHandled || context.IsRequestSkipped || context.IsRejected)
                {
                    return ValueTask.CompletedTask;
                }
                var token = context.Token;
                if (token == null)
                {
                    context.Reject(
                        error: Errors.MissingToken, "Missing Token");

                    return ValueTask.CompletedTask;
                }

                if (context.ValidTokenTypes.Contains("access_token"))
                {
                    try
                    {

                        // perform checking && some custom token validation
                        var isValid = _testTokenService.ValidateToken(token, out var tokenMap);
                        if (!isValid)
                        {
                            context.Reject(
                             error: Errors.InvalidToken, "Invalid Token");

                            return ValueTask.CompletedTask;
                        }
                        if (tokenMap.AccessToken is CustomToken ct)
                        {
                            context.Token = ct.Token;
                        }

                    }
                    catch (Exception ex)
                    {
                        context.Logger.LogError(ex.ToString());
                        context.Reject(
                       error: Errors.InvalidRequest, ex.Message);

                        return ValueTask.CompletedTask;
                    }
                }
                else if (context.ValidTokenTypes.Contains("refresh_token"))
                {
                    if (context.Request?.IsRefreshTokenGrantType() ?? false)
                    {
                        try
                        {
                            var isValid = _testTokenService.ValidateToken(context.Request.RefreshToken, out var tokenMap);
                            if (!isValid)
                            {
                                context.Reject(
                                 error: Errors.InvalidToken, "Invalid Token");

                                return ValueTask.CompletedTask;
                            }
                            context.Request.RefreshToken = tokenMap.RefreshToken.Token;

                        }
                        catch (Exception ex)
                        {
                            context.Logger.LogError(ex.ToString());
                            context.Reject(
                           error: Errors.InvalidRequest, ex.Message);

                            return ValueTask.CompletedTask;
                        }
                    }
                }

                context.Logger.LogTrace(nameof(ServerValidateCustomJsonWebToken));
                return ValueTask.CompletedTask;
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

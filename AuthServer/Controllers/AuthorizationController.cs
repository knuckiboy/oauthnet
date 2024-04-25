using AuthServer.Services;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;

namespace AuthServer.Controllers
{
    public class AuthorizationController : Controller
    {
        private readonly ILogger _logger;
        private readonly TestTokenService _tokenService;
        private readonly IConfiguration _configuration;

        public AuthorizationController(ILogger<AuthorizationController> logger, TestTokenService tokenService, IConfiguration configuration)
        {
            _logger = logger;
            _tokenService = tokenService;
            _configuration = configuration;
        }

        [HttpPost("~/connect/token")]
        public async Task<IActionResult> ExchangeAsync()
        {
            try
            {
                var request = HttpContext.GetOpenIddictServerRequest() ??
                              throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

                ClaimsPrincipal claimsPrincipal;

                if (request.IsClientCredentialsGrantType())
                {
                    // Note: the client credentials are automatically validated by OpenIddict:
                    // if client_id or client_secret are invalid, this action won't be invoked.

                    var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                    // Subject (sub) is a required field, we use the client id as the subject identifier here.
                    identity.AddClaim(OpenIddictConstants.Claims.Subject, request.ClientId ?? throw new InvalidOperationException());

                    // Add some claim, don't forget to add destination otherwise it won't be added to the access token.
                    identity.AddClaim(new Claim("some-claim2", "some-value2").SetDestinations(OpenIddictConstants.Destinations.AccessToken));

                    claimsPrincipal = new ClaimsPrincipal(identity);

                    claimsPrincipal.SetScopes(request.GetScopes());
                }
                else if (request.IsAuthorizationCodeGrantType())
                {
                    // Retrieve the claims principal stored in the authorization code
                    claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
                    string identifier = claimsPrincipal.GetClaim(OpenIddictConstants.Claims.Subject);

                    var userToFailToken = _configuration.GetValue("FailTokenIdentifiers", Array.Empty<string>());
                    if (userToFailToken.Contains(identifier))
                    {
                        return Unauthorized();
                    }
                }

                else
                {
                    throw new InvalidOperationException("The specified grant type is not supported.");
                }
                return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            }
            catch (Exception ex)
            {
                _logger.LogError(ex.ToString());
                throw;
            }

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
        }

        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            try
            {
                var request = HttpContext.GetOpenIddictServerRequest() ??
                    throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

                // Retrieve the user principal stored in the authentication cookie.
                var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                // If the user principal can't be extracted, redirect the user to the login page.
                if (!result.Succeeded)
                {
                    return Challenge(
                        authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                        properties: new AuthenticationProperties
                        {
                            RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                                Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                        });
                }

                // Create a new claims principal
                var claims = new List<Claim>
    {
        // 'subject' claim which is required
        new Claim(OpenIddictConstants.Claims.Subject, result.Principal.Identity.Name),
    };

                var claimsIdentity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
                var properties = new AuthenticationProperties();

                // Set requested scopes (this is not done automatically)
                claimsPrincipal.SetScopes(request.GetScopes());

                var ticket = new AuthenticationTicket(
                claimsPrincipal,
               properties,
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                // Signing in with the OpenIddict authentiction scheme trigger OpenIddict to issue a code (which can be exchanged for an access token)
                var signInResult = SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
                return signInResult;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex.ToString());
                throw;
            }

        }



        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("~/connect/userinfo")]
        public async Task<IActionResult> Userinfo()
        {
            var claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

            return Ok(new
            {
                Name = claimsPrincipal.GetClaim(OpenIddictConstants.Claims.Subject),
                Occupation = "Developer",
                Age = 43
            });
        }

        [HttpGet("~/connect/logout")]
        public async Task<IActionResult> LogoutAsync()
        {
            var bearerToken = HttpContext.Request.Headers.Authorization.ToString();
            var identifier = HttpContext.User.Identity.Name;
            if (!string.IsNullOrEmpty(bearerToken))
            {
                bearerToken = bearerToken.Replace("Bearer ", "");
                await _tokenService.RevokeToken(bearerToken);
            }
            else
            {
                await _tokenService.RevokeTokenByIdentifier(identifier);
            }
            await HttpContext.SignOutAsync();
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
    }
}
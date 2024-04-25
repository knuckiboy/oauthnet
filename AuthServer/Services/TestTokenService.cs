using AuthServer.Data;
using AuthServer.Entities;
using AuthServer.Models;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Core;
using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Services
{
    public class TestTokenService
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly OpenIddictAuthorizationManager<CustomAuthorization> _authorizationManager;
        private readonly OpenIddictTokenManager<CustomToken> _tokenManager;

        public TestTokenService(ApplicationDbContext dbContext, OpenIddictAuthorizationManager<CustomAuthorization> authorizationManager, OpenIddictTokenManager<CustomToken> tokenManager)
        {
            _dbContext = dbContext;
            _authorizationManager = authorizationManager;
            _tokenManager = tokenManager;
        }

        public async Task<TokenMap> GenerateToken(string subject, CustomToken customToken, CustomToken idToken, CustomAuthorization customAuthorization, int length = 255)
        {
            string token = GenerateRandomToken(length);
            var tokenMap = new TokenMap
            {
                Token = token,
                AccessToken = customToken,
                IdToken = idToken,
                CreatedAt = DateTime.UtcNow,
                Authorization = customAuthorization,
                Identifier = subject,
                Status = Status.Valid,
            };
            _dbContext.TokenMaps.Add(tokenMap);
            await _dbContext.SaveChangesAsync();
            return tokenMap;
        }

        private string GenerateRandomToken(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            byte[] data = new byte[length];

            using (RNGCryptoServiceProvider crypto = new())
            {
                crypto.GetBytes(data);
            }

            var tokenBuilder = new StringBuilder(length);
            foreach (byte b in data)
            {
                tokenBuilder.Append(chars[b % (chars.Length)]);
            }

            return tokenBuilder.ToString();
        }

        public bool ValidateToken(string token, out TokenMap tokenMap)
        {
            // TODO: login/logout date validation etc
            tokenMap = _dbContext.TokenMaps.AsNoTracking().Include(x => x.AccessToken).FirstOrDefault(x => string.Equals(x.Token, token));
            return tokenMap != null && tokenMap.Status == Status.Valid;
        }

        public async Task<bool> RevokeToken(string token)
        {
            var tokenMaps = await _dbContext.TokenMaps.Include(x => x.AccessToken).Include(x => x.IdToken).Include(x => x.Authorization).Where(x => string.Equals(x.Token, token) && x.Status == Status.Valid).ToListAsync();
            foreach (var item in tokenMaps)
            {
                await _tokenManager.TryRevokeAsync(item.AccessToken);
                await _tokenManager.TryRevokeAsync(item.IdToken);
                await _authorizationManager.TryRevokeAsync(item.Authorization);
                item.Status = Status.Revoked;
            }
            var result = await _dbContext.SaveChangesAsync();
            return result >= 1;
        }

        public async Task<bool> RevokeTokenByIdentifier(string identifier)
        {
            var tokenMaps = await _dbContext.TokenMaps.Include(x => x.AccessToken).Include(x => x.IdToken).Include(x => x.Authorization).Where(x => x.Identifier == identifier && x.Status == Status.Valid).ToListAsync();
            foreach (var item in tokenMaps)
            {
                await _tokenManager.TryRevokeAsync(item.AccessToken);
                await _tokenManager.TryRevokeAsync(item.IdToken);
                await _authorizationManager.TryRevokeAsync(item.Authorization);
                item.Status = Status.Revoked;
            }
            var result = await _dbContext.SaveChangesAsync();
            return result >= 1;
        }

        public async Task<List<TokenInfo>> RetrieveTokensByIdentifier(string identifier)
        {
            var tokenMaps = _dbContext.TokenMaps.AsNoTracking().Where(x => x.Identifier == identifier && x.Status == Status.Valid);
            var info = await tokenMaps.Select(x => new TokenInfo
            {
                Type = x.AccessToken.Type,
                CreationDate = x.AccessToken.CreationDate ?? default,
                ExpirationDate = x.AccessToken.ExpirationDate ?? default,
                Token = x.AccessToken.Token
            }).ToListAsync();
            return info;
        }

    }
}

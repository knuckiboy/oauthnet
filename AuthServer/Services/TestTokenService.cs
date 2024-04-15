using AuthServer.Data;
using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Services
{
    public class TestTokenService
    {
        private readonly ApplicationDbContext _dbContext;

        public TestTokenService(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<TokenMap> GenerateToken(CustomToken customToken, CustomToken idToken, int length = 255)
        {
            string token = GenerateRandomToken(length);
            var tokenMap = new TokenMap
            {
                Token = token,
                AccessToken = customToken,
                IdToken = idToken,
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
            return tokenMap != null;
        }

    }
}

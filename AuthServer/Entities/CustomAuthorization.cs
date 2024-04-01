using OpenIddict.EntityFrameworkCore.Models;

namespace AuthServer.Entities
{
    public class CustomAuthorization : OpenIddictEntityFrameworkCoreAuthorization<Guid, CustomApplication, CustomToken>
    {
        public string? CustomAuth { get; set; }
    }
}

﻿namespace AuthServer.Entities
{
    public class TokenMap
    {
        public Guid Id { get; set; }

        public string Identifier { get; set; }
        public string Token { get; set; }
        public CustomToken AccessToken { get; set; }
        public CustomToken? IdToken { get; set; }
        public CustomAuthorization Authorization { get; set; }
        public DateTime? CreatedAt { get; set; }
        public Status Status { get; set; }
    }

    public enum Status
    {
        Valid,
        Revoked
    }
}

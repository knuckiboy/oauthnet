namespace AuthServer.Entities
{
    public class TokenMap
    {
        public Guid Id { get; set; }
        public string Token { get; set; }
        public CustomToken CustomToken { get; set; }
    }
}

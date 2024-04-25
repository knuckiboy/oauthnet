namespace AuthServer.Models
{
    public class HomeViewModel
    {
        public List<TokenInfo> Tokens { get; set; }
    }

    public class TokenInfo
    {
        public string Type { get; set; }
        public DateTime CreationDate { get; set; }
        public DateTime ExpirationDate { get; set; }
        public string Token { get; set; }
    }
}

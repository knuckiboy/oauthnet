using System.ComponentModel.DataAnnotations;

namespace AuthServer.Models
{
    public class LoginViewModel
    {
        [Required]
        public string Username { get; set; }
        public string? ReturnUrl { get; set; }
    }
}

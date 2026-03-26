using System.ComponentModel.DataAnnotations;

namespace backend.Application.Auth.Dtos;

public class VerifyEmailDto
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Email is invalid")]
    public string Email { get; set; } = default!;
    
    [Required(ErrorMessage = "Token is required")]
    public string Token { get; set; } = default!;
}




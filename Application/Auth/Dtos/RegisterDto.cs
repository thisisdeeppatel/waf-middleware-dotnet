using System.ComponentModel.DataAnnotations;

namespace backend.Application.Auth.Dtos;

public class RegisterDto
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Email is invalid")]
    public string Email { get; set; } = default!;
    
    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    [MinLength(6, ErrorMessage = "Password must have at least 6 characters")]
    [MaxLength(32, ErrorMessage = "Password must have at max 32 characters")]
    public string Password { get; set; } = default!;
}
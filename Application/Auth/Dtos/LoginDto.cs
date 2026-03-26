using System.ComponentModel.DataAnnotations;

namespace backend.Application.Auth.Dtos;

public class LoginDto
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Email is invalid")]
    public string? Email { get; set; } = null;

    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Text)]
    [MinLength(6, ErrorMessage = "Password must have at least 6 characters")]
    [MaxLength(32, ErrorMessage = "Password must have at max 32 characters")]
    public string? Password { get; set; } = null;
}
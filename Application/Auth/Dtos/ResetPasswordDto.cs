using System.ComponentModel.DataAnnotations;

namespace backend.Application.Auth.Dtos;

public class ResetPasswordDto
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Email is invalid")]
    public string Email { get; set; } = default!;

    [Required(ErrorMessage = "Token is required")]
    public string Token { get; set; } = default!;

    [Required(ErrorMessage = "New password is required")]
    [DataType(DataType.Password)]
    [MinLength(6, ErrorMessage = "Password must have at least 6 characters")]
    [MaxLength(32, ErrorMessage = "Password must have at max 32 characters")]
    public string NewPassword { get; set; } = default!;
}
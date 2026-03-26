using System.ComponentModel.DataAnnotations;

namespace backend.Application.Auth.Dtos;

public class ForgotPasswordDto
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Email is invalid")]
    public string Email { get; set; } = default!;
}




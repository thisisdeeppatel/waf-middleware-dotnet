using System.ComponentModel.DataAnnotations;

namespace backend.Application.Auth.Dtos;

public class ResendVerificationDto
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Email is invalid")]
    public string Email { get; set; } = default!;
}




using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using backend.Application.Auth.Dtos;
using backend.Application.Auth.Response;
using backend.Data.Models;

namespace backend.Application.Auth;

public class AuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _config;
    private readonly ILogger<AuthService> _logger;

    public AuthService(UserManager<ApplicationUser> userManager, IConfiguration config, ILogger<AuthService> logger)
    {
        _userManager = userManager;
        _config = config;
        _logger = logger;
    }

    public async Task<RegisterResponse> RegisterAsync(RegisterDto dto)
    {
        var user = new ApplicationUser { UserName = dto.Email, Email = dto.Email };
        var result = await _userManager.CreateAsync(user, dto.Password);

        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Registration failed: {errors}");
        }

        var adminEmails = _config.GetSection("AdminEmails").Get<string[]>() ?? Array.Empty<string>();
        if (user.Email != null && adminEmails.Contains(user.Email, StringComparer.OrdinalIgnoreCase))
        {
            await _userManager.AddToRoleAsync(user, "Admin");
        }


        var emailConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        _logger.LogInformation("Email confirmation token for {Email}: {Token}", user.Email, emailConfirmationToken);

        return new RegisterResponse { Message = "User registered successfully. Please check your email for confirmation (token logged to server)." };
    }

    public async Task<LoginResponse> LoginAsync(LoginDto dto)
    {
        if (string.IsNullOrEmpty(dto.Email) || string.IsNullOrEmpty(dto.Password))
        {
            throw new UnauthorizedAccessException("Invalid credentials");
        }

        var user = await _userManager.FindByEmailAsync(dto.Email);

        if (user == null || !await _userManager.CheckPasswordAsync(user, dto.Password))
        {
            throw new UnauthorizedAccessException("Invalid credentials");
        }

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email!)
        };

        var roles = await _userManager.GetRolesAsync(user);
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var expireMinutes = _config.GetValue<int>("Jwt:ExpireMinutes", 60);
        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(expireMinutes),
            signingCredentials: creds
        );

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
        return new LoginResponse { Token = tokenString };
    }

    public async Task<ForgotPasswordResponse> ForgotPasswordAsync(ForgotPasswordDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);

        if (user == null)
        {
            throw new KeyNotFoundException("User not found");
        }

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        _logger.LogInformation("Password reset token for {Email}: {Token}", dto.Email, token);
        return new ForgotPasswordResponse { ResetToken = token };
    }

    public async Task<ResetPasswordResponse> ResetPasswordAsync(ResetPasswordDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);

        if (user == null)
        {
            throw new KeyNotFoundException("User not found");
        }

        var result = await _userManager.ResetPasswordAsync(
            user, dto.Token, dto.NewPassword
        );

        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Password reset failed: {errors}");
        }

        return new ResetPasswordResponse { Message = "Password reset successfully" };
    }

    public async Task<VerifyEmailResponse> VerifyEmailAsync(string email, string token)
    {
        var user = await _userManager.FindByEmailAsync(email);

        if (user == null)
        {
            throw new KeyNotFoundException("User not found");
        }

        if (user.EmailConfirmed)
        {
            return new VerifyEmailResponse { Message = "Email is already confirmed" };
        }

        var result = await _userManager.ConfirmEmailAsync(user, token);

        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Email verification failed: {errors}");
        }

        return new VerifyEmailResponse { Message = "Email verified successfully" };
    }

    public async Task<VerifyEmailResponse> ResendVerificationEmailAsync(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);

        if (user == null)
        {
            throw new KeyNotFoundException("User not found");
        }

        if (user.EmailConfirmed)
        {
            throw new InvalidOperationException("Email is already confirmed");
        }

        var emailConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        _logger.LogInformation("Resent email confirmation token for {Email}: {Token}", email, emailConfirmationToken);

        return new VerifyEmailResponse { Message = "Verification email sent (token logged to server)" };
    }

    public async Task<UserProfileResponse> GetUserProfileAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);

        if (user == null)
        {
            throw new KeyNotFoundException("User not found");
        }

        var roles = await _userManager.GetRolesAsync(user);

        return new UserProfileResponse
        {
            Id = user.Id,
            Email = user.Email ?? string.Empty,
            UserName = user.UserName ?? string.Empty,
            EmailConfirmed = user.EmailConfirmed,
            Roles = roles.ToList()
        };
    }
}


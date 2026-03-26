namespace backend.Application.Auth.Response;

public class UserProfileResponse
{
    public string Id { get; set; } = default!;
    public string Email { get; set; } = default!;
    public string UserName { get; set; } = default!;
    public bool EmailConfirmed { get; set; }
    public List<string> Roles { get; set; } = new();
}




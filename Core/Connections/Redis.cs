using StackExchange.Redis;
using System.Text.Json;

namespace backend.Core.Connections;

public class RedisService
{
    private readonly IDatabase _db;

    public RedisService(string connectionString)
    {
        var redis = ConnectionMultiplexer.Connect(connectionString);
        _db = redis.GetDatabase();
    }

    public async Task SetAsync<T>(string key, T value, TimeSpan? expiry = null)
    {
        var json = JsonSerializer.Serialize(value);
        await _db.StringSetAsync(key, json, expiry, When.Always);
    }

    public async Task<T?> GetAsync<T>(string key)
    {
        var value = await _db.StringGetAsync(key);
        if (value.IsNullOrEmpty) return default;

        return JsonSerializer.Deserialize<T>(value.ToString());
    }

    public async Task RemoveAsync(string key)
    {
        await _db.KeyDeleteAsync(key);
    }
}
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

    public async Task<bool> KeyExistsAsync(string key) => await _db.KeyExistsAsync(key);

    public async Task<long> StringIncrementAsync(string key, TimeSpan? expire = null)
    {
        var value = await _db.StringIncrementAsync(key);
        if (value == 1 && expire is { } ttl && ttl > TimeSpan.Zero)
            await _db.KeyExpireAsync(key, ttl);
        return value;
    }
}
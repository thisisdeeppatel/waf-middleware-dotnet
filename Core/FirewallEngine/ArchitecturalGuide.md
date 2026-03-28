# FirewallEngine — C# / ASP.NET Core Explanation

**Scope:** This note explains the .NET patterns used **inside `Core/FirewallEngine` only**. Wiring (e.g. `Program.cs`, Redis, EF registration) is mentioned only where it clarifies how these types are consumed.

**Companion:** Behavior and Redis keys are summarized in [Firewall.md](./Firewall.md).

---

## What lives where

| File | Role |
|------|------|
| `FirewallOptions.cs` | Strongly typed configuration object; maps from `appsettings.json` under section `Firewall`. |
| `FirewallModels.cs` | DTOs and outcomes: `record` types, `enum`, and a small `readonly struct` for decisions. |
| `FirewallScoringEngine.cs` | Stateless scoring from options + request DTO. |
| `FirewallService.cs` | Orchestration: fingerprint, Redis, threshold, rate limit, audit persistence + logging. |
| `WAFMiddleware.cs` | ASP.NET Core middleware: exempt paths, build DTO, call service, short-circuit or `next`. |

---

## NestJS / TypeScript mental map

| Concept here | Rough NestJS / Node analogue |
|--------------|------------------------------|
| **`HttpContext`** | `req` + `res` + connection metadata in one object; also exposes `RequestAborted` (like `req.on('close')` / `AbortSignal`). |
| **`RequestDelegate next`** | Calling `next()` in Express middleware; in C# it is `await next(context)`. |
| **`IMiddleware` + `InvokeAsync`** | Similar to Nest’s middleware class with `use(req, res, next)`, but the framework resolves dependencies per request when the middleware is **transient** (see below). |
| **`IOptions<T>`** | `ConfigService.get('Firewall')` typed as a POCO, but options are bound once at startup unless you use `IOptionsSnapshot` / `IOptionsMonitor` (this project uses plain `IOptions`). |
| **`Configure<T>(section)`** | `ConfigModule` registering a schema + loading from env/files; the section name is `FirewallOptions.SectionName` (`"Firewall"`). |
| **`AddSingleton` / `AddTransient`** | Nest `providers: [{ provide: X, useClass: X }]` with scope: singleton = one instance for app lifetime; transient = new instance **per dependency resolution** (here, **per request** when the pipeline resolves `WAFMiddleware`). |
| **`PathString`** | Typed wrapper around the path segment of the URL; `StartsWithSegments` is the idiomatic prefix check. |
| **`sealed class`** | Class cannot be subclassed; common for infrastructure types where inheritance would break assumptions. |
| **`record`** | Immutable-by-convention data carriers (positional syntax generates constructor, equality, `ToString`). Think typed plain objects with value equality, not `class` identity. |
| **`readonly struct`** | Small value type on the stack when possible; `FirewallDecision` is intentionally not a `record` class to avoid heap allocations for a hot path (minor, but the intent is clear). |
| **`CancellationToken`** | Plumbs cooperative cancellation through async calls (client disconnect, shutdown); pass it to I/O (`WriteAsync`, `SaveChangesAsync`, etc.). |
| **`IDbContextFactory<TContext>`** | Factory for creating short-lived `DbContext` instances. Here the service is **singleton** but must not hold a scoped `DbContext`; the factory creates a context per audit write inside `await using`. Comparable to creating a new query runner / connection scope per operation instead of injecting a request-scoped `EntityManager` for everything. |

---

## Middleware: `WAFMiddleware` and `IMiddleware`

ASP.NET Core supports **convention-based** middleware (a type with `Invoke` / `InvokeAsync` and a specific signature) and **`IMiddleware`**, which this project uses.

**Why it matters:** Types implementing `IMiddleware` are resolved through **DI**. That lets you inject `FirewallService`, `IOptions<FirewallOptions>`, etc., with normal constructor injection—similar to a Nest middleware class that lists providers in its module.

**Registration:** `builder.Services.AddTransient<WAFMiddleware>()` plus `app.UseMiddleware<WAFMiddleware>()`. Transient lifetime means each time the pipeline needs this middleware, DI can construct a fresh instance (so constructor dependencies are satisfied per activation). In practice this behaves like request-scoped middleware instances without declaring custom middleware factories.

**Pipeline contract:** On allow, the code **`await next(context)`** so later middleware and endpoints run. On block/throttle it **never** calls `next`; it writes the response directly. That matches “short-circuit” middleware in Express/Nest.

---

## Configuration: `FirewallOptions` and `IOptions<T>`

`FirewallOptions` is a plain **POCO** (property bag) with defaults. `Program.cs` binds it with:

`Configure<FirewallOptions>(configuration.GetSection(FirewallOptions.SectionName))`.

**In the firewall code:**

- `WAFMiddleware` keeps **`IOptions<FirewallOptions>`** and reads **`_options.Value`** when handling a request. That is the same snapshot for the app lifetime with default `IOptions` behavior.
- `FirewallService` and `FirewallScoringEngine` capture **`options.Value` once in the constructor** into a field. They are registered as **singletons**, so that snapshot is fixed at first resolution—consistent with “config loaded at startup.”

**Collection expressions** (e.g. `PartnerApiKeys { get; set; } = [];`, default whitelist entries) are C# 12 syntax for initializing lists/arrays; equivalent to `new List<string>()` or populated arrays in older C#.

**`TimeSpan`** is a first-class duration type (similar to storing milliseconds in config but here bound as a structured duration for `RateWindow`).

---

## Models: `record`, `enum`, `readonly struct`

**Positional records** (`FirewallRequestDto`, `FirewallScoreSnapshot`, `FirewallAuditRecord`): compiler generates a constructor, equality, and deconstruction support. They are **reference types** (heap) but treated as immutable data in typical usage.

**`BotAction` enum:** Closed set of outcomes; `switch` on `decision.Action` in the middleware is exhaustive if you handle all cases or add a `default` that throws (as in `WriteRejectionAsync`).

**`FirewallDecision` as `readonly struct`:** Factory methods `Allow()`, `Block(reason)`, `Throttle(reason, seconds)` return initialized instances. **`init` accessors** mean properties can only be set during object initialization (object initializer or constructor), not mutated later—similar to `readonly` fields set in a TS constructor.

---

## Scoring: `FirewallScoringEngine`

A **singleton** with no mutable request state; **`Evaluate`** is a pure function of `FirewallRequestDto` + options. In Nest terms, this is a small **provider** you would mark as global/singleton and call from a guard or interceptor—except here it sits behind `FirewallService` rather than being used directly by the middleware.

**APIs used:** `string.Contains(sub, StringComparison.OrdinalIgnoreCase)` for culture-insensitive substring checks; **`Math.Clamp`** to bound the score; **`List<string>`** for factor accumulation.

---

## Service layer: `FirewallService`

**Dependencies:** `IOptions<FirewallOptions>`, `RedisService`, `FirewallScoringEngine`, `IDbContextFactory<ApplicationDbContext>`, `ILogger<FirewallService>`.

**`ILogger<T>`:** Structured logging. The message template uses `{Placeholder}` names; arguments are passed separately—avoid string concatenation so log sinks can index fields. This is the same idea as Nest’s `Logger.log` with context objects, but the API is template-based.

**Cryptography:** `SHA256.Create()` in a **`using var`** block ensures the algorithm instance is disposed. `Convert.ToHexString(hash)` produces the fingerprint string used in Redis keys.

**EF Core:** `await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken)` creates a context, disposes it at the end of the block, and supports async disposal. The **`try` / `catch`** around persistence ensures a DB failure does not break the firewall decision path; errors are logged.

**`JsonSerializer.Serialize(score.Factors)`:** System.Text.Json serializes the factor list for storage—analogous to `JSON.stringify` in TypeScript.

---

## HTTP details in `WAFMiddleware`

- **`PathString`** and **`StartsWithSegments`** for prefix matching with **`StringComparison.OrdinalIgnoreCase`**.
- **`IHeaderDictionary`** and **`TryGetValue`** for safe header reads; **`HeaderNames`** provides canonical header name constants (reduces typos vs raw strings).
- **`context.Connection.RemoteIpAddress`** is `IPAddress?`; **`?.ToString()`** is null-conditional access (like optional chaining in TS).
- **`response.ContentLength`** set before **`WriteAsync`** so the server can send a correct `Content-Length` for the small fixed bodies.
- **`HttpStatusCode` enum** cast to **`int`** for `StatusCode`.
- **`InvalidOperationException`** in the `switch` `default` is a fail-fast guard if `BotAction` is extended without updating the writer.

---

## Summary

FirewallEngine is a small vertical slice: **options binding**, **DI-scoped middleware via `IMiddleware`**, **singleton services** for scoring and orchestration, **records** for data, **`readonly struct`** for lightweight decisions, and **async I/O** threaded with **`CancellationToken`**. If you are comfortable with Nest middleware, guards, and `ConfigService`, the same responsibilities appear here under ASP.NET Core’s naming and lifetimes.

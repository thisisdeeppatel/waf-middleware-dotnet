# Getting started

This document walks through running the project on a Linux workstation. It assumes you are comfortable in a shell, but does not assume prior experience with this codebase.

The application is an ASP.NET Core service on **.NET 10**, backed by **PostgreSQL** and **Redis**. All three need to be available before the API will start cleanly.

---

## 1. Install the .NET 10 SDK

You need the **SDK** (not just the runtime) so you can restore packages, apply EF Core migrations, and run the app.

**Check what you already have:**

```bash
dotnet --list-sdks
```

If you see a line starting with `10.0`, you are done with this section.

**If your distribution packages .NET 10**

On some Ubuntu releases, the SDK is available directly:

```bash
sudo apt update
sudo apt install dotnet-sdk-10.0
```

Availability depends on your distro version and its feeds. If that package does not exist, use one of the options below instead of forcing an older SDK; this project targets `net10.0` and will not build on .NET 8 or 9.

**Portable install (works on most x64 Linux systems)**

Microsoft publishes binary archives and an install script. This avoids tying you to a specific distro’s package timeline.

1. Open the [.NET 10 download page](https://dotnet.microsoft.com/download/dotnet/10.0) and download the **SDK** `.tar.gz` for **Linux x64** (or the architecture that matches your machine).
2. Extract it to a directory you own, for example `~/dotnet`.
3. Add that directory to your `PATH` and set `DOTNET_ROOT` if you plan to use the layout recommended in Microsoft’s install notes:

```bash
export DOTNET_ROOT="$HOME/dotnet"
export PATH="$PATH:$HOME/dotnet"
```

Persist those lines in `~/.bashrc` or `~/.profile` if you want them for every session.

**Alternative: install script**

The script at `https://dot.net/v1/dotnet-install.sh` can install a specific SDK channel. Read the script’s usage (`--help`) and Microsoft’s documentation for `dotnet-install` before running it, especially if you care about install location and updates.

**Sanity check:**

```bash
dotnet --version
```

You should see `10.0.x`.

---

## 2. Clone and configure the project

```bash
git clone <repository-url> waf-dotnet
cd waf-dotnet
dotnet restore
```

**Connection strings**

The API reads configuration from `appsettings.json`, with optional overrides from `appsettings.Development.json` when `ASPNETCORE_ENVIRONMENT` is `Development` (the default when you use the included launch profiles).

The default PostgreSQL connection in `appsettings.json` points at:

- Host `localhost`, port **5433** (not the more common 5432)
- Database `backenddb`, user `root`, password `root`

Either create PostgreSQL to match that, or edit `ConnectionStrings:DefaultConnection` to match your instance. The design-time factory used by EF Core (`ApplicationDbContextFactory`) loads the same JSON files, so `dotnet ef` sees the same connection string as the app.

Redis defaults to `127.0.0.1:6379` via `ConnectionStrings:Redis`. Adjust in `appsettings.json` or `appsettings.Development.json` if your broker listens elsewhere.

**JWT and secrets**

`appsettings.json` contains a placeholder JWT signing key. That is acceptable for local experimentation only. For anything beyond disposable dev environments, use environment variables, user secrets, or a secret store and rotate keys deliberately. This guide does not cover key management; it only flags the risk.

---

## 3. PostgreSQL and Redis

**PostgreSQL**

Create a database and a user that match your connection string (or change the string to match what you already run). Example shape (adjust names and passwords to match `DefaultConnection`):

```bash
psql -U postgres -h localhost -p 5433 -c "CREATE USER root WITH PASSWORD 'root';"
psql -U postgres -h localhost -p 5433 -c "CREATE DATABASE backenddb OWNER root;"
```

If your server uses port 5432, either reconfigure PostgreSQL or change the port in the connection string. Mismatched ports are a frequent source of “cannot connect” errors.

**Redis**

Start `redis-server` (or your managed equivalent) so something is listening on the host and port in `ConnectionStrings:Redis`. The firewall and rate-limiting paths in this project expect Redis to be reachable at startup.

---

## 4. Database migrations

EF Core migrations live under `Migrations/`. Apply them to your database with the **dotnet-ef** tool.

Install the tool once per machine (global install is fine):

```bash
dotnet tool install --global dotnet-ef
```

Ensure the tool is on your `PATH` (the installer usually prints a note if `~/.dotnet/tools` is missing).

From the repository root (the directory that contains `waf-dotnet.csproj`):

```bash
dotnet ef database update
```

That uses `ApplicationDbContextFactory` at design time to build the context and applies pending migrations to the database configured in `appsettings.json`.

If the command fails, read the error carefully: almost always it is a wrong connection string, PostgreSQL not listening, or missing credentials.

---

## 5. Run the API

The launch profiles in `Properties/launchSettings.json` bind HTTP to **5232** in the `http` profile. The included Node load-test script targets that URL.

```bash
dotnet run --launch-profile http
```

Wait until the process logs that it is listening. Then, in another terminal:

```bash
curl -sS http://localhost:5232/api/auth/test-waf
```

You should get a short success payload from that endpoint.

For HTTPS, the `https` profile is also defined; you would need to trust the dev certificate or use `curl -k` if you go that route. The steps below assume HTTP on 5232.

---

## 6. Optional: load test script (Node)

The repository includes `test-endpoint.js`, which uses **autocannon** against `http://localhost:5232/api/auth/test-waf`. It is useful for exercising the WAF and rate limiting, not for unit testing the whole API.

You need a current **Node.js** runtime and npm:

```bash
npm install
node test-endpoint.js
```

Keep the API running with the `http` profile while you do this. If every request fails, verify the port and that nothing else is bound to 5232.
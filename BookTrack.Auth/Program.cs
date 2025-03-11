using BookTrack.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace BookTrack.Auth;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Configure the database context.
        builder.Services.AddDbContext<AppDbContext>(options =>
            options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

        // It’s recommended to add Identity before OpenIddict.
        builder.Services.AddIdentity<IdentityUser, IdentityRole>()
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders();

        // Configure OpenIddict with RSA keys from configuration.
        ConfigureOpenIddict(builder);

        builder.Services.AddControllers();
        builder.Services.AddOpenApi(); // Expose OpenAPI docs for auth endpoints if needed.

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.MapOpenApi();
        }

        app.UseHttpsRedirection();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapControllers();
        app.Run();
    }

    private static void ConfigureOpenIddict(WebApplicationBuilder builder)
    {
        // Load RSA keys from configuration.
        var rsaPrivateKey = builder.Configuration["JwtSettings:PrivateKey"];
        if (string.IsNullOrEmpty(rsaPrivateKey))
        {
            throw new Exception("RSA Private Key not found in configuration.");
        }
        var rsaPublicKey = builder.Configuration["JwtSettings:PublicKey"];
        if (string.IsNullOrEmpty(rsaPublicKey))
        {
            throw new Exception("RSA Public Key not found in configuration.");
        }

        var rsaPriv = RSA.Create();
        rsaPriv.ImportFromPem(rsaPrivateKey.ToCharArray());

        var rsaPub = RSA.Create();
        rsaPub.ImportFromPem(rsaPublicKey.ToCharArray());

        builder.Services.AddOpenIddict()
            .AddCore(options =>
            {
                // Use Entity Framework Core stores.
                options.UseEntityFrameworkCore()
                       .UseDbContext<AppDbContext>();

                // Enables background tasks such as token cleanup.
                options.UseQuartz();
            })
            .AddServer(options =>
            {
                // Configure endpoints.
                options.SetAuthorizationEndpointUris("/connect/authorize")
                       .SetTokenEndpointUris("/connect/token");

                // Allow flows.
                options.AllowPasswordFlow()
                       .AllowRefreshTokenFlow();

                options.AcceptAnonymousClients();

                // Configure RSA keys.
                options.AddSigningKey(new RsaSecurityKey(rsaPriv));
                options.AddEncryptionKey(new RsaSecurityKey(rsaPub));

                // Set token lifetimes.
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(15));
                options.SetRefreshTokenLifetime(TimeSpan.FromMinutes(60)); // Adjust as needed.

                // Configure ASP.NET Core integration.
                options.UseAspNetCore()
                       .EnableTokenEndpointPassthrough()
                       .EnableAuthorizationEndpointPassthrough();
            })
            .AddValidation(options =>
            {
                // For local token validation using the server’s metadata.
                options.UseLocalServer();
                options.UseAspNetCore();
            });
    }
}

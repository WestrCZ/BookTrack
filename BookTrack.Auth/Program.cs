using BookTrack.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace BookTrack.Auth;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

        ConfigureOpenIddict(builder);

        builder.Services.AddControllers();
        builder.Services.AddOpenApi(); // If you want to expose OpenAPI docs for auth endpoints

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
        builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<AppDbContext>();

        options.UseQuartz(); // Enables background tasks like token cleanup (optional)
    })
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token");

        options.AllowPasswordFlow();
        options.AcceptAnonymousClients();

        options.AddEphemeralEncryptionKey();
        options.AddEphemeralSigningKey();

        options.UseAspNetCore()
               .EnableTokenEndpointPassthrough()
               .EnableAuthorizationEndpointPassthrough();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

        builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();
    }
}

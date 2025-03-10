using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using NodaTime;
using BookTrack.Data;
using Microsoft.AspNetCore.Identity;
using BookTrack.Api.Services;
using BookTrack.Api.Interfaces;
using OpenIddict.Validation.AspNetCore;

namespace BookTrack.Api;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        AddServices(builder);
        ConfigureDb(builder);
        ConfigureOpenIddict(builder);
        ConfigureSwagger(builder);

        builder.Services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
            options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme; // Ensure no cookies!
        });

        var app = builder.Build();

        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        app.Run();
    }

    private static void ConfigureSwagger(WebApplicationBuilder builder) =>
            // Configure Swagger with JWT auth support
            builder.Services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Book API", Version = "v1" });

                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "Please enter a valid token",
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    BearerFormat = "JWT",
                    Scheme = "Bearer"
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    new string[] {}
                }
                });
            });
    private static void ConfigureOpenIddict(WebApplicationBuilder builder)
    {
        builder.Services.AddOpenIddict()
                    .AddCore(options =>
                    {
                        options.UseEntityFrameworkCore()
                               .UseDbContext<AppDbContext>();
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

        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Authority = "https://localhost:5001";
                options.Audience = "BookTrackerAPI";
            });
    }

    private static void ConfigureDb(WebApplicationBuilder builder)
    {
        builder.Services.AddDbContext<AppDbContext>(options =>
        {
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
            options.UseNpgsql(connectionString);
        });

        builder.Services.AddIdentity<IdentityUser, IdentityRole>()
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders();
    }

    private static void AddServices(WebApplicationBuilder builder)
    {
        builder.Services.AddScoped<IBookService, BookService>();
        builder.Services.AddSingleton<IClock>(SystemClock.Instance);

        builder.Services.AddControllers();
    }
}

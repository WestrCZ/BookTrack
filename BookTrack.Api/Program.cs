using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using NodaTime;
using BookTrack.Data;
using Microsoft.AspNetCore.Identity;
using BookTrack.Api.Services;
using BookTrack.Api.Interfaces;
using BookTrack.Api.Controllers;

namespace BookTrack.Api;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        AddServices(builder);
        ConfigureDb(builder);
        ConfigureSwagger(builder);
        ConfigureAuth(builder);

        builder.Services.AddControllers()
            .AddApplicationPart(typeof(AuthController).Assembly); // Reference to Auth controllers assembly

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

    private static void ConfigureSwagger(WebApplicationBuilder builder)
    {
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
    }

    private static void ConfigureAuth(WebApplicationBuilder builder)
    {
        // JWT Bearer Authentication for API endpoints
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Authority = "https://localhost:5001"; // The base URL of .Auth server
                options.Audience = "BookTrackerAPI";
            });
    }
}

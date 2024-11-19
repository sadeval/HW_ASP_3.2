using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace HW_ASP_3._2
{
    public class Program
    {
        public static void Main(string[] args)
        {
           
            var builder = WebApplication.CreateBuilder(args);

            var jwtSettings = new JwtSettings();

            builder.Services.AddSingleton(jwtSettings);

            var app = builder.Build();

            app.UseMiddleware<AuthenticationMiddleware>(jwtSettings);

            app.MapWhen(context => context.Request.Path.StartsWithSegments("/secure"), appBuilder =>
            {
                appBuilder.UseMiddleware<JwtMiddleware>(jwtSettings);

                appBuilder.Run(async context =>
                {
                    var username = context.User.Identity.Name;
                    context.Response.ContentType = "text/plain; charset=utf-8";
                    await context.Response.WriteAsync($"Добро пожаловать, {username}! Это защищенный ресурс.");
                });
            });

            app.Map("/public", async context =>
            {
                context.Response.ContentType = "text/plain; charset=utf-8";
                await context.Response.WriteAsync("Это открытый ресурс. Аутентификация не требуется.");
            });

            app.Run();
        }
    }
}

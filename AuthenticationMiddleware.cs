using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace HW_ASP_3._2
{
    public class AuthenticationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly JwtSettings _jwtSettings;

        public AuthenticationMiddleware(RequestDelegate next, JwtSettings jwtSettings)
        {
            _next = next;
            _jwtSettings = jwtSettings;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.Request.Path.Equals("/login", StringComparison.OrdinalIgnoreCase))
            {
                if (context.Request.Method == "POST")
                {
                    // Читаем данные из запроса
                    var form = await context.Request.ReadFormAsync();
                    var username = form["username"];
                    var password = form["password"];

                    // Проверяем логин и пароль
                    if (username == "user" && password == "password")
                    {
                        var token = GenerateJwtToken(username);

                        context.Response.ContentType = "application/json; charset=utf-8";
                        await context.Response.WriteAsync($"{{\"token\":\"{token}\"}}");
                        return;
                    }
                    else
                    {
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        context.Response.ContentType = "text/plain; charset=utf-8";
                        await context.Response.WriteAsync("Неверный логин или пароль.");
                        return;
                    }
                }
                else
                {
                    // Если метод не POST, возвращаем ошибку
                    context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                    context.Response.ContentType = "text/plain; charset=utf-8";
                    await context.Response.WriteAsync("Метод не поддерживается.");
                    return;
                }
            }

            await _next(context);
        }

        private string GenerateJwtToken(string username)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            // Создаем список требований
            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

            // Создаем токен
            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationMinutes),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}

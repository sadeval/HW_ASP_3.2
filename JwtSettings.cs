namespace HW_ASP_3._2
{
    public class JwtSettings
    {
        public string SecretKey { get; set; } = "SecretKey"; // Вставить свой
        public string Issuer { get; set; } = "JwtAuthApi";
        public string Audience { get; set; } = "JwtAuthApiAudience";
        public int ExpirationMinutes { get; set; } = 60;
    }
}

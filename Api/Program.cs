using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Cors;

DateTime started = DateTime.Now;
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("token")//JwtBearerDefaults.AuthenticationScheme)
    .AddOAuth2Introspection("token", opts =>
    {
        opts.Authority = "https://localhost:5001";
        opts.ClientId = "api1";
        opts.ClientSecret = "secret";
    });
    //.AddJwtBearer(opts =>
    //{
    //    opts.Authority = "https://localhost:5001";
    //    opts.TokenValidationParameters.ValidateAudience = false;
    //});

builder.Services.AddAuthorization(opts => {
    opts.AddPolicy("scope1", policy => policy.RequireAuthenticatedUser().RequireClaim("scope", "scope1"));
    opts.AddPolicy("scope2", policy => policy.RequireAuthenticatedUser().RequireClaim("scope", "scope2"));
    opts.AddPolicy("scope3", policy => policy.RequireAuthenticatedUser().RequireClaim("scope", "scope3"));
    opts.AddPolicy("scope2|scope3", policy => policy.RequireAuthenticatedUser().RequireClaim("scope", "scope2", "scope3"));
});

builder.Services.AddCors(opts => {
    opts.AddPolicy("spa.policy", policy => { policy.WithOrigins("https://localhost:5003").AllowAnyHeader().AllowAnyMethod(); });
});

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();

app.UseCors("spa.policy");

app.UseAuthentication();
app.UseAuthorization();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", (HttpContext ctx) =>
{
    var claims = ctx.User.Claims.Select(x => new { name = x.Type, value = x.Value });

    var forecast = Enumerable.Range(1, 5).Select(index =>
       new WeatherForecast
       (
           DateTime.Now.AddDays(index),
           Random.Shared.Next(-20, 55),
           summaries[Random.Shared.Next(summaries.Length)]
       ))
        .ToArray();
    return Results.Json(new { claims, forecast });
}).RequireAuthorization("scope2|scope3");

app.MapGet("/statistics", (HttpContext ctx) =>
{
    var claims = ctx.User.Claims.Select(x => new { name = x.Type, value = x.Value }).ToArray();
    return Results.Json(new {
        user = claims,
        appName = app.Environment.ApplicationName,
        wwwRoot = app.Environment.WebRootPath,
        contentRoot = app.Environment.ContentRootPath,
        environment = app.Environment.EnvironmentName,
        now = DateTime.Now,
        started
    });
}).RequireAuthorization("scope1");

app.Run();

internal record WeatherForecast(DateTime Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
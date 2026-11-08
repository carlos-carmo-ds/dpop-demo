using System.Security.Claims;
using DpopDemo.Api.Dpop;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var keycloak = builder.Configuration.GetSection("Keycloak");
var authority = keycloak["Authority"] ?? throw new InvalidOperationException("Keycloak:Authority não configurado.");
var audience = keycloak["Audience"] ?? throw new InvalidOperationException("Keycloak:Audience não configurado.");

const string RawTokenItem = "dpop:access_token";
const string DpopErrorItem = "dpop:error";

builder.Services.AddMemoryCache();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.Configure<DpopOptions>(builder.Configuration.GetSection("Dpop"));
builder.Services.AddSingleton<DpopProofValidator>();

builder.Services.AddCors(options => options.AddPolicy("web", policy => policy
    .WithOrigins(builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [])
    .WithMethods("GET", "POST")
    .WithHeaders("Authorization", "DPoP", "Content-Type")
    .WithExposedHeaders("WWW-Authenticate", "DPoP-Nonce")));

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Valida o access token com as chaves públicas do Keycloak (/.well-known/openid-configuration -> jwks_uri).
        options.Authority = authority;
        options.RequireHttpsMetadata = keycloak.GetValue("RequireHttpsMetadata", true);

        // Opcional: endereço que a API usa para buscar o discovery/JWKS quando ele difere da URL
        // pública do Keycloak (ex.: no cluster, "localhost:8080" do navegador não é alcançável;
        // a API usa "host.k3d.internal:8080"). O issuer esperado continua sendo a Authority.
        var metadataAddress = keycloak["MetadataAddress"];
        if (!string.IsNullOrWhiteSpace(metadataAddress))
            options.MetadataAddress = metadataAddress;
        options.MapInboundClaims = false; // mantém os nomes originais: sub, preferred_username, cnf...
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = authority,
            ValidAudience = audience,
            NameClaimType = "preferred_username",
            ClockSkew = TimeSpan.FromSeconds(30),
        };

        options.Events = new JwtBearerEvents
        {
            // O JwtBearer só entende "Authorization: Bearer ...". Aqui lemos "Authorization: DPoP ...".
            OnMessageReceived = context =>
            {
                var authorization = context.Request.Headers.Authorization.ToString();

                if (authorization.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase))
                {
                    var token = authorization["DPoP ".Length..].Trim();
                    context.Token = token;
                    context.HttpContext.Items[RawTokenItem] = token;
                }
                else if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    // Esta API só aceita DPoP. Aceitar Bearer permitiria usar um token roubado sem a chave.
                    context.HttpContext.Items[DpopErrorItem] = "invalid_token";
                    context.Fail("Esta API exige o esquema DPoP; tokens Bearer não são aceitos.");
                }

                return Task.CompletedTask;
            },

            // Token válido (assinatura, iss, aud, exp). Agora valida a prova DPoP.
            OnTokenValidated = async context =>
            {
                var validator = context.HttpContext.RequestServices.GetRequiredService<DpopProofValidator>();
                var accessToken = (string)context.HttpContext.Items[RawTokenItem]!;

                var result = await validator.ValidateAsync(context.Request, accessToken);
                if (!result.IsValid)
                {
                    context.HttpContext.Items[DpopErrorItem] = result.Error;
                    context.Fail(result.Description!);
                    return;
                }

                (context.Principal?.Identity as ClaimsIdentity)?.AddClaim(new Claim("dpop_jkt", result.Jkt!));
            },

            // Resposta 401 no formato da RFC 9449: WWW-Authenticate: DPoP ...
            OnChallenge = async context =>
            {
                context.HandleResponse();

                var error = context.HttpContext.Items[DpopErrorItem] as string
                            ?? (context.AuthenticateFailure is null ? null : "invalid_token");
                var description = context.AuthenticateFailure?.Message;

                var header = $"DPoP algs=\"{string.Join(' ', DpopProofValidator.SupportedAlgorithms)}\"";
                if (error is not null) header += $", error=\"{error}\"";

                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.Headers.WWWAuthenticate = header;
                await context.Response.WriteAsJsonAsync(new
                {
                    error = error ?? "unauthorized",
                    error_description = description ?? "Envie Authorization: DPoP <token> e o header DPoP.",
                });
            },
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseCors("web");          // antes da autenticação, para que as respostas 401 também tenham CORS
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));

app.MapGet("/api/me", (ClaimsPrincipal user) => Results.Ok(new
{
    message = "Access token e prova DPoP válidos.",
    sub = user.FindFirstValue("sub"),
    username = user.Identity?.Name,
    email = user.FindFirstValue("email"),
    dpopKeyThumbprint = user.FindFirstValue("dpop_jkt"),
    serverTimeUtc = DateTimeOffset.UtcNow,
}))
.RequireAuthorization();

app.Run();

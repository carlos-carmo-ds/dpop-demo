using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace DpopDemo.Api.Dpop;

public sealed class DpopOptions
{
    /// <summary>
    /// URL base da API como o CLIENT a enxerga (usada para conferir o "htu").
    /// Atrás de proxy/gateway ela é diferente da URL interna do Kestrel.
    /// </summary>
    public string? PublicBaseUrl { get; set; }

    /// <summary>Por quanto tempo uma prova é aceita a partir do "iat".</summary>
    public int ProofLifetimeSeconds { get; set; } = 60;

    /// <summary>Tolerância para relógio do client adiantado.</summary>
    public int ClockSkewSeconds { get; set; } = 5;
}

public sealed record DpopValidationResult(bool IsValid, string? Error, string? Description, string? Jkt)
{
    public static DpopValidationResult Success(string jkt) => new(true, null, null, jkt);

    public static DpopValidationResult InvalidProof(string description) =>
        new(false, "invalid_dpop_proof", description, null);

    public static DpopValidationResult InvalidToken(string description) =>
        new(false, "invalid_token", description, null);
}

/// <summary>
/// Valida a prova DPoP (RFC 9449, seção 4.3) de uma requisição a um resource server.
/// O access token em si (assinatura, iss, aud, exp) já foi validado pelo JwtBearer antes.
/// </summary>
public sealed class DpopProofValidator(
    IMemoryCache replayCache,
    IOptions<DpopOptions> options,
    TimeProvider time,
    ILogger<DpopProofValidator> logger)
{
    /// <summary>Somente algoritmos assimétricos: "none" e HMAC (HS*) nunca são aceitos.</summary>
    public static readonly string[] SupportedAlgorithms = ["ES256", "PS256", "RS256"];

    private static readonly object ReplayLock = new();
    private readonly JsonWebTokenHandler _handler = new();
    private readonly DpopOptions _options = options.Value;

    public async Task<DpopValidationResult> ValidateAsync(HttpRequest request, string accessToken)
    {
        var result = await ValidateCoreAsync(request, accessToken);
        if (!result.IsValid)
        {
            logger.LogInformation("DPoP rejeitado em {Method} {Path}: {Reason}",
                request.Method, request.Path, result.Description);
        }
        return result;
    }

    private async Task<DpopValidationResult> ValidateCoreAsync(HttpRequest request, string accessToken)
    {
        // 1. Exatamente um header DPoP.
        var values = request.Headers["DPoP"];
        if (values.Count != 1 || string.IsNullOrWhiteSpace(values[0]))
            return DpopValidationResult.InvalidProof("Header DPoP ausente ou duplicado.");
        var proof = values[0]!;

        // 2. Lê o cabeçalho da prova: typ, alg e jwk (chave pública).
        JsonWebKey jwk;
        try
        {
            var parts = proof.Split('.');
            if (parts.Length != 3)
                return DpopValidationResult.InvalidProof("Prova DPoP não é um JWS compacto.");

            using var header = JsonDocument.Parse(Base64UrlEncoder.Decode(parts[0]));
            var root = header.RootElement;

            if (!root.TryGetProperty("typ", out var typ) || typ.GetString() != "dpop+jwt")
                return DpopValidationResult.InvalidProof("typ da prova deve ser 'dpop+jwt'.");

            if (!root.TryGetProperty("alg", out var alg) || !SupportedAlgorithms.Contains(alg.GetString()))
                return DpopValidationResult.InvalidProof("alg da prova ausente ou não suportado.");

            if (!root.TryGetProperty("jwk", out var jwkElement) || jwkElement.ValueKind != JsonValueKind.Object)
                return DpopValidationResult.InvalidProof("Header 'jwk' ausente na prova.");

            jwk = new JsonWebKey(jwkElement.GetRawText());
            if (!string.IsNullOrEmpty(jwk.D))
                return DpopValidationResult.InvalidProof("A 'jwk' da prova não pode conter chave privada.");
        }
        catch (Exception ex) when (ex is JsonException or FormatException or ArgumentException)
        {
            return DpopValidationResult.InvalidProof("Prova DPoP malformada.");
        }

        // 3. Assinatura da prova, conferida com a própria jwk que veio no header.
        var validation = await _handler.ValidateTokenAsync(proof, new TokenValidationParameters
        {
            IssuerSigningKey = jwk,
            ValidAlgorithms = SupportedAlgorithms,
            ValidTypes = ["dpop+jwt"],
            RequireSignedTokens = true,
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,       // a prova não tem "exp"; o "iat" é checado abaixo
            RequireExpirationTime = false,
        });
        if (!validation.IsValid || validation.SecurityToken is not JsonWebToken token)
            return DpopValidationResult.InvalidProof("Assinatura da prova DPoP inválida.");

        // 4. htm: método HTTP desta requisição.
        if (!token.TryGetPayloadValue<string>("htm", out var htm) || htm != request.Method)
            return DpopValidationResult.InvalidProof($"htm '{htm}' não corresponde ao método {request.Method}.");

        // 5. htu: URL desta requisição (sem query string e fragmento).
        var expectedHtu = BuildExpectedHtu(request);
        if (!token.TryGetPayloadValue<string>("htu", out var htu) || !HtuMatches(htu, expectedHtu))
            return DpopValidationResult.InvalidProof($"htu '{htu}' não corresponde a '{expectedHtu}'.");

        // 6. iat: a prova precisa ser recente.
        if (token.IssuedAt == DateTime.MinValue)
            return DpopValidationResult.InvalidProof("iat ausente na prova.");
        var now = time.GetUtcNow();
        var iat = new DateTimeOffset(token.IssuedAt, TimeSpan.Zero);
        if (iat > now.AddSeconds(_options.ClockSkewSeconds))
            return DpopValidationResult.InvalidProof("iat da prova está no futuro.");
        if (iat < now.AddSeconds(-_options.ProofLifetimeSeconds))
            return DpopValidationResult.InvalidProof("Prova DPoP expirada (iat muito antigo).");

        // 7. ath: hash do access token, amarra a prova a ESTE token.
        var expectedAth = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
        if (!token.TryGetPayloadValue<string>("ath", out var ath) || ath != expectedAth)
            return DpopValidationResult.InvalidProof("ath não corresponde ao access token enviado.");

        // 8. cnf.jkt: o token foi emitido para ESTA chave?
        var expectedJkt = ReadCnfJkt(accessToken);
        if (expectedJkt is null)
            return DpopValidationResult.InvalidToken("O access token não está vinculado a DPoP (cnf.jkt ausente).");
        var jkt = Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
        if (jkt != expectedJkt)
            return DpopValidationResult.InvalidProof("A chave da prova não é a chave à qual o token foi vinculado.");

        // 9. jti: cada prova só pode ser usada uma vez (proteção contra replay).
        //    Em produção, com várias instâncias da API, use um cache distribuído (ex.: Redis).
        if (string.IsNullOrEmpty(token.Id))
            return DpopValidationResult.InvalidProof("jti ausente na prova.");
        var replayKey = $"dpop-jti:{jkt}:{token.Id}";
        lock (ReplayLock)
        {
            if (replayCache.TryGetValue(replayKey, out _))
                return DpopValidationResult.InvalidProof("Prova DPoP reutilizada (jti já visto).");
            replayCache.Set(replayKey, true,
                TimeSpan.FromSeconds(_options.ProofLifetimeSeconds + _options.ClockSkewSeconds));
        }

        return DpopValidationResult.Success(jkt);
    }

    private Uri BuildExpectedHtu(HttpRequest request)
    {
        var baseUrl = string.IsNullOrWhiteSpace(_options.PublicBaseUrl)
            ? $"{request.Scheme}://{request.Host}"
            : _options.PublicBaseUrl.TrimEnd('/');
        return new Uri(baseUrl + request.PathBase + request.Path);
    }

    private static bool HtuMatches(string? htu, Uri expected) =>
        Uri.TryCreate(htu, UriKind.Absolute, out var actual)
        && Uri.Compare(actual, expected,
            UriComponents.SchemeAndServer | UriComponents.Path,
            UriFormat.SafeUnescaped, StringComparison.Ordinal) == 0;

    private static string? ReadCnfJkt(string accessToken)
    {
        // O token já teve a assinatura validada pelo JwtBearer; aqui só lemos o claim "cnf".
        var parts = accessToken.Split('.');
        if (parts.Length < 2) return null;
        using var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(parts[1]));
        return payload.RootElement.TryGetProperty("cnf", out var cnf)
               && cnf.ValueKind == JsonValueKind.Object
               && cnf.TryGetProperty("jkt", out var jkt)
               && jkt.ValueKind == JsonValueKind.String
            ? jkt.GetString()
            : null;
    }
}

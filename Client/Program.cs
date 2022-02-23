using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseStatusCodePages();

Client.InitDiscovery();

app.MapGet("/m2m", async () => {
    HttpClient client = Client.Instance;
    
    DiscoveryDocumentResponse discovery = await Client.DiscoveryCache.GetAsync();
    if(discovery.IsError) return Results.Json(new { error = "Can't discovery endpoint: https://localhost:5001/" });

    var tokenRequest = new ClientCredentialsTokenRequest
    {
        Address = discovery.TokenEndpoint,
        
        GrantType = "client_credentials",

        ClientId = "m2m.client",
        ClientSecret = "511536EF-F270-4058-80CA-1C89C192F69A",
        Scope = "scope1"
    };
    TokenResponse token = await client.RequestClientCredentialsTokenAsync(tokenRequest);
    if(token.IsError) return Results.Json(new { error = $"Can't retrieve token. {token.Error}: {token.ErrorDescription}" });

    client.SetBearerToken(token.AccessToken);
    HttpResponseMessage resp = await client.GetAsync("https://localhost:5002/statistics");

    if(!resp.IsSuccessStatusCode) return Results.Json(new { error = $"API Error: {resp.StatusCode}:{resp.ReasonPhrase}"});

    ApiResult? res = await resp.Content.ReadFromJsonAsync<ApiResult>();

    return Results.Json(new { items = res });
});

string rsaKey = "{'kty':'RSA','e':'AQAB','use':'sig','d':'Buddpe5mllPnDihVMWp_N6-Fe93Ry25QQ2VOZU6vsrKvRjuoyDvmlF7KPI9zdZV8ZD7VFt1O0tsSb6vXOwHhFuOA4ItsE1bzjokl1xV079oZl0hdACyucW_xunK4Lkk5A-NyrOAvcNOASdq-nZIIRv6G6f7paRIS9LPP_Y-h4Hs_uwTfewCjY5ER5b6WCxskBrcbONx28EE6_raW_BQrotrZUsN0mHv8uHiSTEMbTgO_Ylwvueis6Uud3LIWugk8Gti_4ptIRe_UI8-WKGIiZ9cXN5M-MKaboJ4ddv4g3LrZAg7FOI_r7u-hxNLsu-_x6FhvKHk8Ea86Zy9Bze_rwQ','p':'x5sK5Vv3BOTcHlKkpu699IOjmmYhmvsJI-5aeCpVfiZ_-efizddZMhQwhNpbhbM_DnDLI3mse-sOa3kWliETcYB0j5L0DBI9EpQlkz5yfACQCb6S8-NHKdLcx2_yYqbnWib-ivc79vYvnM1IH3-FnNwyjB4gJeKJhSKIFVLvwXc','q':'po6CyLWoT6tY2L3hODdAh4QFh4OsckBZ9TXGWZgh4yj8XxPXPJAc9ne6PBueWPVRf1RjIOiDsMbvk1BNv5s-NADxK19lnm9uOny3CbDynHt8q2qVgfuCPVO0pEbUff7Tai79Hzz0DAbssJlqiuhGPVsUq5VLtu6NQzYoXDIWEtk','kid':'bHmeq41SMrvnlyjP7_v8nK2IT4hvNV28EvH9hG_ybUk','qi':'oVVMyDylFdkMnJ14TtjfLt4bEiAtQyRm86fwzkKBf9JGXESNtG61r8TnnC6Dd8Uj1a3wqh8uXkwn7PMKthdkP6j2NqOQnyDA-dAjWUuwTX_t2F0CchFkjWvhZYBqn1nPIQkopokZvCGhmc6mMAY2X-aRY4msiVcJCverrDmRkBo','dp': 'Qp2L1WAL4KZAkB4ktVGYM7J7N1w-euqs8kDqEJCQV7mhnFW3a9si-YOjbbMyODzKHpemNAC3f-PCvDt9Pj1rr8WfIQt6R00O9NRcdfexXZESgS4I_Tws09h7tlO2IRZyv7Oj390DNjiTS1F3cIuum9shQ4IKWJpyKuyLXhJ_0aE','dq':'OrJOdN1QC4OfNAL2tBEEtL1aFX_Z7gmvqjLhTAHJL3zqM7eSSs2e510aTMSO8VrC9dSPerF2d34kQA402Cmlqj4Kv_ZGoaczeXkqKEgrt-ns7ZwKRFyWcXZmWt57VEvRxcH5gmDAwNxP3Yyzd3CUEFtg1Xcvz7ASKHWVk6gzD0E','n':'gd2nCf8oBqYp4ya_wtfHuosblUH1gszWGIKhQeqeOl7JGvY6ezNZE3_ALDYU8aro6G4FtYWPvInw6wFjjXRlwEOVT_eFo-7fMNd3o_PzdTOKiRumGfz1kyIIZ8jv6JcFX0MzdXt3sp9iRGlBkPKdnSgc15Lp9H_a4HXpLPD4EpremsFMetpJ_1cqtNtipxwbLKFW0MyRQLCi-68y8ps3gMCMiXN0NYnwcUQDcmfDHOKoq99bdn9x6P46LjOAqAk08SXbhiDbrg7MArvW1Y1F5H_aY9PxToh32M8AhDGO2ugoVWEDNgj1FzyvTvEXEgXjpH4kqcBBjNlcXO0QBw9b3w','kid':'bHmeq41SMrvnlyjP7_v8nK2IT4hvNV28EvH9hG_ybUk','alg':'RS256','n':'gd2nCf8oBqYp4ya_wtfHuosblUH1gszWGIKhQeqeOl7JGvY6ezNZE3_ALDYU8aro6G4FtYWPvInw6wFjjXRlwEOVT_eFo-7fMNd3o_PzdTOKiRumGfz1kyIIZ8jv6JcFX0MzdXt3sp9iRGlBkPKdnSgc15Lp9H_a4HXpLPD4EpremsFMetpJ_1cqtNtipxwbLKFW0MyRQLCi-68y8ps3gMCMiXN0NYnwcUQDcmfDHOKoq99bdn9x6P46LjOAqAk08SXbhiDbrg7MArvW1Y1F5H_aY9PxToh32M8AhDGO2ugoVWEDNgj1FzyvTvEXEgXjpH4kqcBBjNlcXO0QBw9b3w'}";
//string rsaKey = "{'d':'GmiaucNIzdvsEzGjZjd43SDToy1pz-Ph-shsOUXXh-dsYNGftITGerp8bO1iryXh_zUEo8oDK3r1y4klTonQ6bLsWw4ogjLPmL3yiqsoSjJa1G2Ymh_RY_sFZLLXAcrmpbzdWIAkgkHSZTaliL6g57vA7gxvd8L4s82wgGer_JmURI0ECbaCg98JVS0Srtf9GeTRHoX4foLWKc1Vq6NHthzqRMLZe-aRBNU9IMvXNd7kCcIbHCM3GTD_8cFj135nBPP2HOgC_ZXI1txsEf-djqJj8W5vaM7ViKU28IDv1gZGH3CatoysYx6jv1XJVvb2PH8RbFKbJmeyUm3Wvo-rgQ','dp':'YNjVBTCIwZD65WCht5ve06vnBLP_Po1NtL_4lkholmPzJ5jbLYBU8f5foNp8DVJBdFQW7wcLmx85-NC5Pl1ZeyA-Ecbw4fDraa5Z4wUKlF0LT6VV79rfOF19y8kwf6MigyrDqMLcH_CRnRGg5NfDsijlZXffINGuxg6wWzhiqqE','dq':'LfMDQbvTFNngkZjKkN2CBh5_MBG6Yrmfy4kWA8IC2HQqID5FtreiY2MTAwoDcoINfh3S5CItpuq94tlB2t-VUv8wunhbngHiB5xUprwGAAnwJ3DL39D2m43i_3YP-UO1TgZQUAOh7Jrd4foatpatTvBtY3F1DrCrUKE5Kkn770M','e':'AQAB','kid':'ZzAjSnraU3bkWGnnAqLapYGpTyNfLbjbzgAPbbW2GEA','kty':'RSA','n':'wWwQFtSzeRjjerpEM5Rmqz_DsNaZ9S1Bw6UbZkDLowuuTCjBWUax0vBMMxdy6XjEEK4Oq9lKMvx9JzjmeJf1knoqSNrox3Ka0rnxXpNAz6sATvme8p9mTXyp0cX4lF4U2J54xa2_S9NF5QWvpXvBeC4GAJx7QaSw4zrUkrc6XyaAiFnLhQEwKJCwUw4NOqIuYvYp_IXhw-5Ti_icDlZS-282PcccnBeOcX7vc21pozibIdmZJKqXNsL1Ibx5Nkx1F1jLnekJAmdaACDjYRLL_6n3W4wUp19UvzB1lGtXcJKLLkqB6YDiZNu16OSiSprfmrRXvYmvD8m6Fnl5aetgKw','p':'7enorp9Pm9XSHaCvQyENcvdU99WCPbnp8vc0KnY_0g9UdX4ZDH07JwKu6DQEwfmUA1qspC-e_KFWTl3x0-I2eJRnHjLOoLrTjrVSBRhBMGEH5PvtZTTThnIY2LReH-6EhceGvcsJ_MhNDUEZLykiH1OnKhmRuvSdhi8oiETqtPE','q':'0CBLGi_kRPLqI8yfVkpBbA9zkCAshgrWWn9hsq6a7Zl2LcLaLBRUxH0q1jWnXgeJh9o5v8sYGXwhbrmuypw7kJ0uA3OgEzSsNvX5Ay3R9sNel-3Mqm8Me5OfWWvmTEBOci8RwHstdR-7b9ZT13jk-dsZI7OlV_uBja1ny9Nz9ts','qi':'pG6J4dcUDrDndMxa-ee1yG4KjZqqyCQcmPAfqklI2LmnpRIjcK78scclvpboI3JQyg6RCEKVMwAhVtQM6cBcIO3JrHgqeYDblp5wXHjto70HVW6Z8kBruNx1AH9E8LzNvSRL-JVTFzBkJuNgzKQfD0G77tQRgJ-Ri7qu3_9o1M4'}";

app.MapGet("/m2m-jwk", async () => {
    HttpClient client = Client.Instance;

    DiscoveryDocumentResponse discovery = await Client.DiscoveryCache.GetAsync();
    if (discovery.IsError) return Results.Json(new { error = "Can't discovery endpoint: https://localhost:5001/" });
    
    var jwk = new JsonWebKey(rsaKey);
    var creds = new SigningCredentials(jwk, "RS256");
    string clientToken = Client.CreateClientToken(creds, "m2m.client.jwt", discovery.TokenEndpoint);

    var tokenRequest = new ClientCredentialsTokenRequest
    {
        Address = discovery.TokenEndpoint,

        GrantType = "client_credentials",

        ClientAssertion = new ClientAssertion
        {
            Type = OidcConstants.ClientAssertionTypes.JwtBearer,
            Value = clientToken
        },
        
        Scope = "scope1"
    };

    TokenResponse token = await client.RequestClientCredentialsTokenAsync(tokenRequest);
    if (token.IsError) return Results.Json(new { error = $"Can't retrieve token. {token.Error}: {token.ErrorDescription}" });

    client.SetBearerToken(token.AccessToken);
    HttpResponseMessage resp = await client.GetAsync("https://localhost:5002/statistics");

    if (!resp.IsSuccessStatusCode) return Results.Json(new { error = $"API Error: {resp.StatusCode}:{resp.ReasonPhrase}" });

    ApiResult? res = await resp.Content.ReadFromJsonAsync<ApiResult>();

    return Results.Json(new { items = res });
});

app.MapPost("/ciba", async (CibaLogin model) =>
{
    HttpClient client = Client.Instance;

    DiscoveryDocumentResponse discovery = await Client.DiscoveryCache.GetAsync();
    if (discovery.IsError) return Results.Json(new { error = "Can't discovery endpoint: https://localhost:5001/" });

    var request = new BackchannelAuthenticationRequest
    {
        Address = discovery.BackchannelAuthenticationEndpoint,
        
        ClientId = "ciba.client",
        ClientSecret = "D6AD724F-070D-4CCA-96D0-279E5D42B271",

        Scope = "openid scope2",
        
        LoginHint = model.Login,
        BindingMessage = model.Binding
    };

    BackchannelAuthenticationResponse resp = await client.RequestBackchannelAuthenticationAsync(request);
    if(resp.IsError) return Results.Json(new { error = $"CIBA error: {resp.Error}" });

    return Results.Json(new { requestId = resp.AuthenticationRequestId, expires = resp.ExpiresIn, interval = resp.Interval });
});

app.MapGet("/ciba-token/{id}", async (string id) =>
{
    HttpClient client = Client.Instance;

    DiscoveryDocumentResponse discovery = await Client.DiscoveryCache.GetAsync();
    if (discovery.IsError) return Results.Json(new { error = "Can't discovery endpoint: https://localhost:5001/" });
    
    var request = new BackchannelAuthenticationTokenRequest
    {
        Address = discovery.TokenEndpoint,
        
        ClientId = "ciba.client",
        ClientSecret = "D6AD724F-070D-4CCA-96D0-279E5D42B271",

        AuthenticationRequestId = id
    };

    TokenResponse resp = await client.RequestBackchannelAuthenticationTokenAsync(request);

    if(resp.IsError) {
        bool continueLoop = resp.Error == "authorization_pending" || resp.Error == "slow_down";
        return Results.Json(new { result = false, continueLoop });
    }

    return Results.Json(new { result = true, token = resp.AccessToken });
});

app.MapGet("/delegate-token/{token}/{style}", async (string token, string style) =>
{
    HttpClient client = Client.Instance;

    DiscoveryDocumentResponse discovery = await Client.DiscoveryCache.GetAsync();
    if(discovery.IsError) return Results.Json(new { error = "Can't discovery endpoint: https://localhost:5001/" });

    var request = new TokenExchangeTokenRequest
    {
        Address = discovery.TokenEndpoint,
        ClientId = "tokenExchange.client",
        ClientSecret = "7E42CFD4-D8D4-4F96-A416-0BE336B2A82A",

        SubjectToken = token,
        SubjectTokenType = OidcConstants.TokenTypeIdentifiers.AccessToken,
        Scope = "scope2",
        
        Parameters =
        {
            { "exchange_style", style }
        }
    };

    TokenResponse resp = await client.RequestTokenExchangeTokenAsync(request);
    if(resp.IsError) return Results.Json(new { error = $"Exchange error: {resp.Error}"});

    return Results.Json(new { access_token = resp.AccessToken });
});

app.Run();

internal static class Client
{
    private static HttpClient? _instance;
    public static HttpClient Instance => _instance ??= new HttpClient();

    private static DiscoveryCache? _disco;
    public static DiscoveryCache DiscoveryCache => _disco!;

    public static void InitDiscovery() => _disco = new DiscoveryCache("https://localhost:5001");

    public static string CreateClientToken(SigningCredentials credential, string clientId, string tokenEndpoint)
    {
        var now = DateTime.UtcNow;

        var token = new JwtSecurityToken(
            clientId,
            tokenEndpoint,
            new List<Claim>()
            {
            new Claim(JwtClaimTypes.JwtId, Guid.NewGuid().ToString()),
            new Claim(JwtClaimTypes.Subject, clientId),
            new Claim(JwtClaimTypes.IssuedAt, now.ToEpochTime().ToString(), ClaimValueTypes.Integer64)
            },
            now,
            now.AddMinutes(1),
            credential
        );

        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.WriteToken(token);
    }
}

internal class ApiResult
{
    public string? AppName { get; set; }
    public string? WwwRoot { get; set; }
    public string? ContentRoot { get; set; }
    public string? Environment { get; set; }
    public DateTime Started { get; set; }
    public DateTime Now { get; set; }
    public ApiResultItems[]? User { get; set; }
}

internal class ApiResultItems
{
    public string? Name { get; set; }
    public string? Value { get; set; }
}

internal class CibaLogin
{
    public string? Login { get; set; }
    public string? Binding { get; set; }
}
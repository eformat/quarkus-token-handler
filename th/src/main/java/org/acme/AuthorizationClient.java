package org.acme;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.mutiny.core.MultiMap;
import io.vertx.mutiny.core.Vertx;
import io.vertx.mutiny.ext.web.client.HttpResponse;
import io.vertx.mutiny.ext.web.client.WebClient;
import org.acme.data.AuthorizationRequestData;
import org.acme.data.CookieName;
import org.acme.exceptions.ForbiddenException;
import org.acme.exceptions.InvalidStateException;
import org.acme.exceptions.UnauthorizedException;
import org.apache.http.entity.ContentType;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.core.Response;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

@ApplicationScoped
public class AuthorizationClient {

    private final Logger log = LoggerFactory.getLogger(AuthorizationClient.class);

    @ConfigProperty(name = "authServer")
    String authServer;

    @ConfigProperty(name = "redirectUri")
    String redirectUri;

    @ConfigProperty(name = "clientId")
    String clientId;

    @ConfigProperty(name = "clientSecret")
    String clientSecret;

    @ConfigProperty(name = "realm")
    String realm;

    @ConfigProperty(name = "cookieExpiresSec")
    int cookieExpiresSec;

    @Inject
    Vertx vertx;

    @Inject
    Util util;

    @Inject
    CookieName cookieName;

    public JsonObject getTokens(String encryptedCookie, TokenHandlerResource.OAuthQueryParams queryParams) throws UnauthorizedException {
        if (null == encryptedCookie) {
            throw new ForbiddenException("No temporary login cookie found");
        }
        String decryptedCookie = util.decryptCookieValue(encryptedCookie);
        AuthorizationRequestData authorizationRequestData = null;
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            authorizationRequestData = objectMapper.readValue(decryptedCookie, AuthorizationRequestData.class);
        } catch (JsonProcessingException e) {
            e.printStackTrace(); // FIXME
        }
        if (!authorizationRequestData.getState().equals(queryParams.state())) {
            throw new InvalidStateException("Login cookie is invalid");
        }
        Uni<JsonObject> response = exchangeCodeForTokens(queryParams.code(), authorizationRequestData.getCodeVerifier());
        return response.await().indefinitely();
    }

    public Uni<JsonObject> exchangeCodeForTokens(String code, String codeVerifier) {
        MultiMap form = MultiMap.caseInsensitiveMultiMap();
        form.add("grant_type", "authorization_code"); // OAuth 2.0 Authorization Code Grant https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1
        form.add("code", code); // Auth code
        form.add("redirect_uri", redirectUri);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret); // Client Credentials (cannot be accessed using Client Credentials Grant, as service account disabled in auth server)
        form.add("code_verifier", codeVerifier); // PKCE
        WebClientOptions options = new WebClientOptions().setKeepAlive(true).setSsl(true).setVerifyHost(false).setTrustAll(true); // FIXME Trust CA
        return WebClient.create(vertx, options)
                .postAbs(authServer + "/auth/realms/" + realm + "/protocol/openid-connect/token")
                .putHeader("Content-Type", ContentType.APPLICATION_FORM_URLENCODED.toString())
                .sendForm(form)
                .onItem().transform(HttpResponse::bodyAsJsonObject);
        //.onFailure(); FIXME error handler
    }

    public JsonObject refreshAccessToken(String encryptedCookie) {
        String decryptedCookie = util.decryptCookieValue(encryptedCookie);
        MultiMap form = MultiMap.caseInsensitiveMultiMap();
        form.add("grant_type", "refresh_token");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("refresh_token", decryptedCookie);
        WebClientOptions options = new WebClientOptions().setKeepAlive(true).setSsl(true).setVerifyHost(false).setTrustAll(true); // FIXME Trust CA
        Uni<JsonObject> response = WebClient.create(vertx, options)
                .postAbs(authServer + "/auth/realms/" + realm + "/protocol/openid-connect/token")
                .putHeader("Content-Type", ContentType.APPLICATION_FORM_URLENCODED.toString())
                .sendForm(form)
                .onItem().transform(HttpResponse::bodyAsJsonObject); //.onFailure(); FIXME error handler
        return response.await().indefinitely();
    }

    public AuthorizationRequestData getAuthRequestData() {
        MultiMap form = MultiMap.caseInsensitiveMultiMap();
        String state = null;
        String codeVerifier = null;
        try {
            state = util.generateRandomString(64);
            codeVerifier = util.generateRandomString(64);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidStateException("Crypto failed to generate");
        }
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("state", state); // we should check this ourselves
        form.add("response_mode", "jwt"); // see .well-known/openid-configuration [response_modes_supported] (JARM)
        form.add("response_type", "code"); // OAuth 2.0 Authorization Code Grant https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1
        form.add("scope", "openid"); // we will get an ID token using openid scope when we exchange
        form.add("code_challenge", util.getCodeChallenge(codeVerifier)); // PKCE
        form.add("code_challenge_method", "S256"); // PCKE method
        form.add("redirect_uri", redirectUri); // we set this so must match realm settings
        // OAuth 2.0 Pushed Authorization Requests
        WebClientOptions options = new WebClientOptions().setKeepAlive(true).setSsl(true).setVerifyHost(false).setTrustAll(true); // FIXME Trust CA
        Uni<JsonObject> response = WebClient.create(vertx, options)
                .postAbs(authServer + "/auth/realms/" + realm + "/protocol/openid-connect/ext/par/request")
                .putHeader("Content-Type", ContentType.APPLICATION_FORM_URLENCODED.toString())
                .sendForm(form)
                .onItem().transform(HttpResponse::bodyAsJsonObject); //.onFailure(); FIXME error handler

        JsonObject res = response.await().indefinitely();
        if (null != res.getString("error") && !res.getString("error").isEmpty()) {
            throw new ForbiddenException("Cannot authenticate to PAR endpoint");
        }

        JsonObject urlObject = new JsonObject().put("authorizationRequestUrl", authServer + "/auth/realms/" + realm + "/protocol/openid-connect/auth?client_id=" + clientId + "&request_uri=" + res.getString("request_uri"));
        return new AuthorizationRequestData(codeVerifier, state, urlObject);
    }

    /*

        suspend fun getAuthorizationRequestObjectUri(state: String, codeVerifier: String): String
    {
        println("*** DEBUG")
        println(config.redirectUri)
        var body =
            "client_id=${config.clientID}&state=${state}&response_mode=jwt&response_type=code&redirect_uri=${config.redirectUri}&code_challenge=${codeVerifier.hash()}&code_challenge_method=S256"

        if (config.scope != null)
        {
            body += "&scope=${config.scope}"
        }

        try
        {
            val parResponse = client.post()
                .uri(config.authorizeEndpoint + "/par")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .bodyValue(body)
                .awaitExchange { response -> handleAuthorizationServerResponse<PARResponse>(response, "PAR") }

            return "${config.authorizeExternalEndpoint}?client_id=${config.clientID}&request_uri=${parResponse.requestUri}"
        } catch (exception: WebClientRequestException)
        {
            throw AuthorizationServerException("Exception encountered when calling authorization server", exception)
        }
    }
}

class PARResponse(
    @JsonProperty("request_uri") val requestUri: String,
    @JsonProperty("expires_in") val expiresIn: Int
)

        if (re)
            if (response.statusCode().is5xxServerError)
            {
                throw AuthorizationServerException("Server error response in $grant: ${response.awaitBody<String>()}")
            }

            if (response.statusCode().is4xxClientError)
            {
                throw UnauthorizedException("$grant request was rejected: ${response.awaitBody<String>()}")
            }

            return response.awaitBody()
        }

     */

    public void getCookiesForTokenResponse(Response.ResponseBuilder responseBuilder, JsonObject tokenResponse, boolean unsetLoginCookie, String csrfToken) {
        String expires = "";
        if (cookieExpiresSec > -1) {
            expires = "; Max-Age=" + cookieExpiresSec;
            ZonedDateTime expiry = ZonedDateTime.now().plusSeconds(cookieExpiresSec);
            expires += "; Expires=" + expiry.format(DateTimeFormatter.RFC_1123_DATE_TIME);
        }
        if (null != tokenResponse) {
            if (tokenResponse.getString("id_token") != null && !tokenResponse.getString("id_token").isEmpty()) {
                responseBuilder
                        .header("Set-Cookie", cookieName.ID() + "=" + util.encryptCookieValue(tokenResponse.getString("id_token")) + "; Secure; HttpOnly; SameSite=strict; Domain=.example.com; Path=/;" + expires);
            }
            if (tokenResponse.getString("access_token") != null && !tokenResponse.getString("access_token").isEmpty()) {
                responseBuilder
                        .header("Set-Cookie", cookieName.ACCESS() + "=" + util.encryptCookieValue(tokenResponse.getString("access_token")) + "; Secure; HttpOnly; SameSite=strict; Domain=.example.com; Path=/;" + expires);
            }
            if (tokenResponse.getString("refresh_token") != null && !tokenResponse.getString("refresh_token").isEmpty()) {
                responseBuilder
                        .header("Set-Cookie", cookieName.REFRESH() + "=" + util.encryptCookieValue(tokenResponse.getString("refresh_token")) + "; Secure; HttpOnly; SameSite=strict; Domain=.example.com; Path=/;" + expires);
            }
        }
        if (null != csrfToken && !csrfToken.isEmpty()) {
            responseBuilder
                    .header("Set-Cookie", cookieName.CSRF() + "=" + util.encryptCookieValue(csrfToken) + "; Secure; HttpOnly; SameSite=strict; Domain=.example.com; Path=/;" + expires);
        }
        if (unsetLoginCookie) {
            var epoch = Instant.EPOCH.atZone(ZoneOffset.UTC);
            responseBuilder
                    .header("Set-Cookie", cookieName.LOGIN() + "=; Secure; HttpOnly; SameSite=strict; Domain=.example.com; Path=/; Expires=" + epoch.format(DateTimeFormatter.RFC_1123_DATE_TIME));
        }
    }

    public void getCookiesForUnset(Response.ResponseBuilder responseBuilder) {
        var epoch = Instant.EPOCH.atZone(ZoneOffset.UTC);
        responseBuilder
                .header("Set-Cookie", cookieName.ID() + "=" + "; Secure; HttpOnly; SameSite=strict; Domain=.example.com; Path=/; Expires=" + epoch.format(DateTimeFormatter.RFC_1123_DATE_TIME))
                .header("Set-Cookie", cookieName.ACCESS() + "=" + "; Secure; HttpOnly; SameSite=strict; Domain=.example.com; Path=/; Expires=" + epoch.format(DateTimeFormatter.RFC_1123_DATE_TIME))
                .header("Set-Cookie", cookieName.REFRESH() + "=" + "; Secure; HttpOnly; SameSite=strict; Domain=.example.com; Path=/; Expires=" + epoch.format(DateTimeFormatter.RFC_1123_DATE_TIME))
                .header("Set-Cookie", cookieName.CSRF() + "=" + "; Secure; HttpOnly; SameSite=strict; Domain=.example.com; Path=/; Expires=" + epoch.format(DateTimeFormatter.RFC_1123_DATE_TIME));
    }

    public JsonObject logout(String encryptedCookie) {
        String decryptedCookie = util.decryptCookieValue(encryptedCookie);
        MultiMap form = MultiMap.caseInsensitiveMultiMap();
        form.add("redirect_uri", redirectUri);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("refresh_token", decryptedCookie);
        WebClientOptions options = new WebClientOptions().setKeepAlive(true).setSsl(true).setVerifyHost(false).setTrustAll(true); // FIXME Trust CA
        WebClient.create(vertx, options)
                .postAbs(authServer + "/auth/realms/" + realm + "/protocol/openid-connect/logout")
                .putHeader("Content-Type", ContentType.APPLICATION_FORM_URLENCODED.toString())
                .sendForm(form)
                .onItem().transform(HttpResponse::bodyAsJsonObject)
                .await().indefinitely();//.onFailure(); FIXME error handler
        return new JsonObject().put("url", redirectUri);
    }
}

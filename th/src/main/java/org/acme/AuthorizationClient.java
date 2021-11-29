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
import org.acme.data.TokenResponse;
import org.acme.exceptions.InvalidStateException;
import org.acme.exceptions.UnauthorizedException;
import org.apache.http.entity.ContentType;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.security.NoSuchAlgorithmException;

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

    @Inject
    Vertx vertx;

    @Inject
    Util util;

    public TokenResponse getTokens(String encryptedCookie, TokenHandlerResource.OAuthQueryParams queryParams) throws UnauthorizedException {
        TokenResponse tokenResponse = null;
        if (null == encryptedCookie) {
            throw new UnauthorizedException("No temporary login cookie found");
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
        log.info(">>> response " + response.await().indefinitely());
        return tokenResponse;
    }

    public Uni<JsonObject> exchangeCodeForTokens(String code, String codeVerifier) {
        MultiMap form = MultiMap.caseInsensitiveMultiMap();
        form.add("grant_type","authorization_code"); // OAuth 2.0 Authorization Code Grant https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1
        form.add("code", code); // Auth code
        form.add("redirect_uri", redirectUri);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret); // Client Credentials (cannot be accessed using Client Credentials Grant, as service account disabled in auth server)
        form.add("code_verifier", codeVerifier); // PKCE
        WebClientOptions options = new WebClientOptions().setKeepAlive(true).setSsl(true).setVerifyHost(false).setTrustAll(true); // FIXME Trust CA
        return WebClient.create(vertx, options)
                .postAbs(authServer + "/auth/realms/bff/protocol/openid-connect/token")
                .putHeader("Content-Type", ContentType.APPLICATION_FORM_URLENCODED.toString())
                .sendForm(form)
                .onItem().transform(HttpResponse::bodyAsJsonObject);
                //.onFailure(); FIXME error handler
    }

    public AuthorizationRequestData getAuthRequestData() {
        StringBuilder url = new StringBuilder();
        String state = null;
        String codeVerifier = null;
        try {
            state = util.generateRandomString(64);
            codeVerifier = util.generateRandomString(64);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace(); // FIXME Exception Handling
        }
        url.append(authServer + "/auth/realms/bff/protocol/openid-connect/auth?");
        url.append("client_id=" + clientId);
        url.append("&state=" + state); // we should check this ourselves
        url.append("&response_type=code"); // OAuth 2.0 Authorization Code Grant https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1
        url.append("&scope=openid"); // we will get an ID token using openid scope when we exchange
        url.append("&code_challenge=" + util.getCodeChallenge(codeVerifier)); // PKCE
        url.append("&code_challenge_method=S256"); // PCKE method
        url.append("&redirect_uri=" + redirectUri); // we set this so must match realm settings
        JsonObject urlObject = new JsonObject().put("authorizationRequestUrl", url.toString());
        return new AuthorizationRequestData(codeVerifier, state, urlObject);
    }
}

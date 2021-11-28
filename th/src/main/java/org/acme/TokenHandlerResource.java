package org.acme;

import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Path("/tokenhandler")
public class TokenHandlerResource {

    private final Logger log = LoggerFactory.getLogger(TokenHandlerResource.class);

    @Inject
    Util util;

    private SecretKey key = null;
    private IvParameterSpec ivParameterSpec = null;

    @POST
    @Path("/login/start")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response loginStart() {
        log.info("loginStart");

        // FIXME - Validate request origin

        /*

function getAuthorizationURL(config: BFFConfiguration): AuthorizationRequestData {
    const codeVerifier = generateRandomString()
    const state = generateRandomString()

    let authorizationRequestUrl = config.authorizeEndpoint + "?" +
        "client_id=" + encodeURIComponent(config.clientID) +
        "&state=" + encodeURIComponent(state) +
        "&response_type=code" +
        "&redirect_uri=" + encodeURIComponent(config.redirectUri) +
        "&code_challenge=" + generateHash(codeVerifier) +
        "&code_challenge_method=S256"

    if (config.scope) {
        authorizationRequestUrl += "&scope=" + encodeURIComponent(config.scope)
    }

    return new AuthorizationRequestData(authorizationRequestUrl, codeVerifier, state)
}

        const authorizationRequestData = getAuthorizationURL(config)

        res.setHeader('Set-Cookie',
            getTempLoginDataCookie(authorizationRequestData.codeVerifier, authorizationRequestData.state, config.cookieOptions, config.cookieNamePrefix, config.encKey))
        res.status(200).json({
            authorizationRequestUrl: authorizationRequestData.authorizationRequestURL
        })

{
  "authorizationRequestUrl": "https://idsvr.example.com/oauth/authorize?client_id=bff_client&response_type=code&scope=openid%20read&redirect_uri=https://www.example.com/"
}
         */

        StringBuilder url = new StringBuilder();
        String state = null;
        String codeVerifier = null;
        try {
            state = util.generateRandomString(64);
            codeVerifier = util.generateRandomString(64);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        url.append("https://login.example.com:8443/auth/realms/bff/protocol/openid-connect/auth?"); // https://localhost:8443/auth/realms/master/protocol/openid-connect/auth
        url.append("client_id=bff_client");
        url.append("&state=" + state);
        url.append("&response_type=code");
        url.append("&scope=openid");
        url.append("&code_challenge=" + util.getCodeChallenge(codeVerifier));
        url.append("&code_challenge_method=S256");
        url.append("&redirect_uri=https://www.example.com/");

        // FIXME - Set cookie
        // https://quarkus.io/guides/security-openid-connect-web-authentication#oidc-cookies

        /*
function getTempLoginDataCookie(codeVerifier: string, state: string, options: CookieSerializeOptions, cookieNamePrefix: string, encKey: string): string {
    return serialize(getTempLoginDataCookieName(cookieNamePrefix), encryptCookie(encKey, JSON.stringify({ codeVerifier, state })), options)
}

    encKey: 'NF65meV>Ls#8GP>;!Cnov)rIPRoK^.NP', // 32-character long string,
    cookieNamePrefix: 'example',
    bffEndpointsPrefix: '/bff',
    cookieOptions: {
        httpOnly: true,
        sameSite: true,
        secure: false,
        domain: '.example.com',
        path: '/',
    } as CookieSerializeOptions,
         */
        String cipherText = null;
        try {
            key = util.generateKey(128);
            ivParameterSpec = util.generateIv();
            String algorithm = "AES/CBC/PKCS5Padding";
            cipherText = util.encrypt(algorithm, state, key, ivParameterSpec);
            String plainText = util.decrypt(algorithm, cipherText, key, ivParameterSpec);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        JsonObject ret = new JsonObject().put("authorizationRequestUrl", url.toString());
        return Response.ok(ret)
                .header("Set-Cookie", "example-login=" + cipherText + "; HttpOnly; SameSite=strict; Domain=.example.com; Path=/; MaxAge=-1") // FIXME - add Secure when https, cookie name
                .build();
    }

    @POST
    @Path("/login/end")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response loginEnd(@CookieParam("example") NewCookie cookie, Request request) {
        log.info("loginEnd " + request);
        // FIXME - Validate request origin
        // FIXME - logic to check for an OAuth response
        // Check for cookie
        if (null != cookie) {
            String algorithm = "AES/CBC/PKCS5Padding";
            try {
                log.info("cookie: " + cookie);
                String plainText = util.decrypt(algorithm, cookie.getName(), key, ivParameterSpec);
                log.info("cookie: " + plainText);
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }

        JsonObject ret = new JsonObject()
                .put("handled", true)
                .put("isLoggedIn", false);
        return Response.ok(ret).build();
    }

    @GET
    @Path("/userInfo")
    public String userInfo() {
        log.info("userInfo");
        return "userInfo";
    }

    @POST
    @Path("/logout")
    public String logout() {
        log.info("logout");
        return "logout";
    }

    @POST
    @Path("/refresh")
    public String refresh() {
        log.info("refresh");
        return "refresh";
    }

}

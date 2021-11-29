package org.acme;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.json.JsonObject;
import org.acme.data.AuthorizationRequestData;
import org.acme.data.CookieName;
import org.acme.data.ValidateRequestOptions;
import org.acme.exceptions.UnauthorizedException;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.jboss.resteasy.reactive.RestResponse;
import org.jboss.resteasy.reactive.server.core.ResteasyReactiveRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.util.List;

@Path("/tokenhandler")
public class TokenHandlerResource {

    private final Logger log = LoggerFactory.getLogger(TokenHandlerResource.class);

    @Inject
    Util util;

    @Inject
    RequestValidator requestValidator;

    @Inject
    CookieName cookieName;

    @Inject
    AuthorizationClient authorizationClient;

    record OAuthQueryParams(String code, String state) {
    }

    @POST
    @Path("/login/start")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response loginStart(@Context ResteasyReactiveRequestContext context) {
        log.info("loginStart");

        try {
            requestValidator.validateRequest(context, new ValidateRequestOptions(true, false)); // FIXME ValidateRequestOptions
        } catch (UnauthorizedException ex) {
            log.warn(ex.getMessage());
            return Response.status(ex.getStatusCode()).build();
        }

        AuthorizationRequestData authRequestData = authorizationClient.getAuthRequestData();

        // Cookie Options are important here as they determine token security in SPA
        return Response.ok(authRequestData.getUrl())
                .header("Set-Cookie", cookieName.LOGIN() + "=" + util.encryptCookieValue(getCookieValue(authRequestData)) + "; Secure; HttpOnly; SameSite=strict; Domain=.example.com; Path=/; MaxAge=-1")
                .build();
    }

    @POST
    @Path("/login/end")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response loginEnd(@Context ResteasyReactiveRequestContext context, String body) {
        log.info("loginEnd");
        try {
            requestValidator.validateRequest(context, new ValidateRequestOptions(true, false)); // FIXME ValidateRequestOptions
        } catch (UnauthorizedException ex) {
            log.warn(ex.getMessage());
            return Response.status(ex.getStatusCode()).build();
        }

        // see if we have an openid post back url from identity server with code and state
        OAuthQueryParams queryParams = null;
        try {
            queryParams = getOAuthQueryParams(body);
        } catch (Exception ex) {
            log.warn(ex.getMessage());
            return Response.status(RestResponse.StatusCode.BAD_REQUEST).build();
        }
        boolean isOAuthResponse = queryParams.state != null && queryParams.code != null;

        boolean isLoggedIn = false;
        String csrfToken = null;
        Response.ResponseBuilder responseBuilder = Response.ok();

        if (isOAuthResponse) {
            JsonObject tokenResponse = null;
            try {
                tokenResponse = authorizationClient.getTokens(context.getCookieParameter(cookieName.LOGIN()), queryParams);
            } catch (UnauthorizedException ex) {
                log.warn(ex.getMessage());
                return Response.status(ex.getStatusCode()).build();
            }
            if (null == context.getCookieParameter(cookieName.CSRF())) {
                try {
                    csrfToken = util.generateRandomString(64);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace(); // FIXME Exception Handling
                }
            } else {
                csrfToken = util.decryptCookieValue(context.getCookieParameter(cookieName.CSRF()));
            }
            // Write the SameSite cookies
            authorizationClient.getCookiesForTokenResponse(responseBuilder, tokenResponse, true, csrfToken);
            isLoggedIn = true;

        } else {
            // See if we have an access token cookie
            isLoggedIn = context.getCookieParameter(cookieName.ACCESS()) != null;

            if (isLoggedIn && null != context.getCookieParameter(cookieName.CSRF())) {
                // During an authenticated page refresh or opening a new browser tab, we must return the anti forgery token
                // This enables an XSS attack to get the value, but this is standard for CSRF tokens
                csrfToken = util.decryptCookieValue(context.getCookieParameter(cookieName.CSRF()));
            }
        }

        JsonObject ret = new JsonObject()
                .put("handled", isOAuthResponse)
                .put("isLoggedIn", isLoggedIn)
                .put("csrfToken", csrfToken);
        return responseBuilder.entity(ret).build();
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

    private OAuthQueryParams getOAuthQueryParams(String body) throws URISyntaxException {
        if (null == body || body.length() == 0) {
            return new OAuthQueryParams(null, null);
        }
        JsonObject pageUrl = new JsonObject(body);
        List<NameValuePair> params = URLEncodedUtils.parse(new URI(pageUrl.getValue("pageUrl").toString()), Charset.forName("UTF-8"));
        String code = null;
        String state = null;
        for(NameValuePair nvp : params) { // FIXME clumsy
            switch (nvp.getName()) {
                case "code":
                    code = nvp.getValue();
                    break;
                case "state":
                    state = nvp.getValue();
                    break;
            }
        }
        return new OAuthQueryParams(code, state);
    }

    private String getCookieValue(AuthorizationRequestData authRequestData) {
        String cookieValue = null;
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            cookieValue = objectMapper.writeValueAsString(authRequestData);
        } catch (JsonProcessingException e) {
            e.printStackTrace(); // FIXME
        }
        return cookieValue;
    }

}

package org.acme;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonObject;
import org.acme.data.AuthorizationRequestData;
import org.acme.data.CookieName;
import org.acme.data.ValidateRequestOptions;
import org.acme.exceptions.ForbiddenException;
import org.acme.exceptions.InvalidStateException;
import org.acme.exceptions.UnauthorizedException;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.resteasy.reactive.RestResponse;
import org.jboss.resteasy.reactive.server.core.ResteasyReactiveRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
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

    @Inject
    JWTParser parser;

    record OAuthQueryParams(String code, String state) {
    }

    @POST
    @Path("/login/start")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response loginStart(@Context ResteasyReactiveRequestContext context) {
        log.info("loginStart");

        try {
            requestValidator.validateRequest(context, new ValidateRequestOptions(true, false));
        } catch (ForbiddenException ex) {
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
        log.info(body);
        try {
            requestValidator.validateRequest(context, new ValidateRequestOptions(true, false));
        } catch (ForbiddenException ex) {
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
            log.debug(">>> tokenResponse: " + tokenResponse.encode());

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
                .put("csrf", csrfToken);
        return responseBuilder.entity(ret).build();
    }

    @GET
    @Path("/userInfo")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response userInfo(@Context ResteasyReactiveRequestContext context) {
        log.info("userInfo");

        try {
            requestValidator.validateRequest(context, new ValidateRequestOptions(true, false));
        } catch (ForbiddenException ex) {
            log.warn(ex.getMessage());
            return Response.status(ex.getStatusCode()).build();
        }

        String jsonResult = null;
        if (null != context.getCookieParameter(cookieName.ID()) && !context.getCookieParameter(cookieName.ID()).isEmpty()) {
            String decrytedCookie = null;
            try {
                 decrytedCookie = util.decryptCookieValue(context.getCookieParameter(cookieName.ID()));
            } catch (ForbiddenException ex) {
                log.warn(ex.getMessage());
                return Response.status(ex.getStatusCode()).build();
            }
            String[] parts = decrytedCookie.split("\\.");
            if (parts.length != 3) {
                log.warn("ID Cookie malformed");
                return Response.status(RestResponse.StatusCode.BAD_REQUEST).build();
            }

            try {
                ObjectMapper objectMapper = new ObjectMapper();
                HashMap id = objectMapper.readValue(Base64.getDecoder().decode(parts[1]), HashMap.class);
                jsonResult = objectMapper.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(id);

            } catch (JsonProcessingException e) {
                e.printStackTrace(); // FIXME
            } catch (IOException e) {
                e.printStackTrace();
            }

        } else {
            log.warn("No cookie was supplied during user info");
            return Response.status(RestResponse.StatusCode.UNAUTHORIZED).build();
        }

        return Response.ok(jsonResult).build();
    }

    @POST
    @Path("/logout")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response logout(@Context ResteasyReactiveRequestContext context) {
        log.info("logout");

        try {
            requestValidator.validateRequest(context, new ValidateRequestOptions(true, true));
        } catch (ForbiddenException ex) {
            log.warn(ex.getMessage());
            return Response.status(ex.getStatusCode()).build();
        }

        Response.ResponseBuilder responseBuilder = Response.ok();
        JsonObject logout = null;
        if (null != context.getCookieParameter(cookieName.REFRESH()) && !context.getCookieParameter(cookieName.REFRESH()).isEmpty()) {
            authorizationClient.getCookiesForUnset(responseBuilder);
            logout = authorizationClient.logout(context.getCookieParameter(cookieName.REFRESH()));
        } else {
            log.warn("No cookie was supplied during logout");
            return Response.status(RestResponse.StatusCode.UNAUTHORIZED).build();
        }

        return responseBuilder.entity(logout).build();
    }

    @POST
    @Path("/refresh")
    public Response refresh(@Context ResteasyReactiveRequestContext context) {
        log.info("refresh"); // FIXME SPA does not call this yet?

        try {
            requestValidator.validateRequest(context, new ValidateRequestOptions(true, true));
        } catch (ForbiddenException ex) {
            log.warn(ex.getMessage());
            return Response.status(ex.getStatusCode()).build();
        }

        Response.ResponseBuilder responseBuilder = Response.ok();
        JsonObject tokenResponse = null;

        if (null != context.getCookieParameter(cookieName.REFRESH()) && !context.getCookieParameter(cookieName.REFRESH()).isEmpty()) {
            authorizationClient.getCookiesForUnset(responseBuilder);
            tokenResponse = authorizationClient.refreshAccessToken(context.getCookieParameter(cookieName.REFRESH()));
            String csrfToken = null;
            if (null == context.getCookieParameter(cookieName.CSRF())) {
                log.warn("No csrf cookie was supplied during refresh");
                return Response.status(RestResponse.StatusCode.UNAUTHORIZED).build();
            } else {
                csrfToken = util.decryptCookieValue(context.getCookieParameter(cookieName.CSRF()));
            }
            // Write the SameSite cookies
            authorizationClient.getCookiesForTokenResponse(responseBuilder, tokenResponse, false, csrfToken);
        } else {
            log.warn("No cookie was supplied during refresh");
            return Response.status(RestResponse.StatusCode.UNAUTHORIZED).build();
        }

        return responseBuilder.build();
    }

    private OAuthQueryParams getOAuthQueryParams(String body) throws URISyntaxException, ParseException, InvalidStateException, DecodeException {
        if (null == body || body.length() == 0) {
            return new OAuthQueryParams(null, null);
        }

        JsonObject pageUrl = new JsonObject(body);
        if (null == pageUrl.getValue("pageUrl")) {
            return new OAuthQueryParams(null, null);
        }
        List<NameValuePair> params = URLEncodedUtils.parse(new URI(pageUrl.getValue("pageUrl").toString()), Charset.forName("UTF-8"));
        String response = null;
        for (NameValuePair nvp : params) {
            switch (nvp.getName()) {
                case "response":
                    response = nvp.getValue();
                    break;
            }
        }
        if (null == response) {
            return new OAuthQueryParams(null, null);
        }

        // validated against auth server
        JsonWebToken jwt = parser.parse(response);

        return new OAuthQueryParams(jwt.getClaim("code"), jwt.getClaim("state"));
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

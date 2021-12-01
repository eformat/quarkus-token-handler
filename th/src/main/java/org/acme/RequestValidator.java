package org.acme;

import org.acme.data.CookieName;
import org.acme.data.ValidateRequestOptions;
import org.acme.exceptions.ForbiddenException;
import org.acme.exceptions.UnauthorizedException;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.resteasy.reactive.server.core.ResteasyReactiveRequestContext;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

@ApplicationScoped
public class RequestValidator {

    @Inject
    Util util;

    @Inject
    CookieName cookieName;

    @ConfigProperty(name = "trustedWebOrigins")
    String trustedWebOrigins;

    public void validateRequest(ResteasyReactiveRequestContext context, ValidateRequestOptions options) throws UnauthorizedException {
        _validate(
                (context.getHeader("x-example-csrf", true) == null ? null : context.getHeader("x-example-csrf", true).toString()),
                context.getCookieParameter(cookieName.CSRF()),
                (context.getHeader("Origin", true) == null ? null : context.getHeader("Origin", true).toString()),
                options
        );
    }

    private void _validate(String csrfHeader, String encryptedCookie, String origin, ValidateRequestOptions options) throws UnauthorizedException {

        if (options.requireTrustedOrigin == true) {
            if (origin == null || !trustedWebOrigins.contains(origin)) {
                throw new ForbiddenException("The call is from an untrusted web origin: " + origin);
            }
        }

        if (options.requireCsrfHeader == true) {
            if (null == encryptedCookie || encryptedCookie.isEmpty()) {
                throw new ForbiddenException("No csrf cookie");
            }
            String decryptedCookie = util.decryptCookieValue(encryptedCookie);
            if (null == csrfHeader || csrfHeader.isEmpty()) {
                throw new ForbiddenException("Csrf header empty");
            }
            if (!csrfHeader.equals(decryptedCookie)) {
                throw new ForbiddenException("Csrf match failed");
            }
        }
    }

}

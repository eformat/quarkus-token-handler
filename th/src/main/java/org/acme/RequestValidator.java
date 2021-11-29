package org.acme;

import org.acme.data.ValidateRequestOptions;
import org.acme.exceptions.UnauthorizedException;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.resteasy.reactive.server.core.ResteasyReactiveRequestContext;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class RequestValidator {

    @ConfigProperty(name = "trustedWebOrigins")
    String trustedWebOrigins;

    public void validateRequest(ResteasyReactiveRequestContext context, ValidateRequestOptions options) throws UnauthorizedException {
        _validate(
                (context.getHeader("X-example-csrf", true) == null ? null : context.getHeader("X-example-csrf", true).toString()),
                context.getCookieParameter("example-login"),
                (context.getHeader("Origin", true) == null ? null : context.getHeader("Origin", true).toString()),
                options
        );
    }

    private void _validate(String csrfHeader, String csrfCookie, String origin, ValidateRequestOptions options) throws UnauthorizedException {

        if (origin == null || !trustedWebOrigins.contains(origin)) {
            throw new UnauthorizedException("The call is from an untrusted web origin: " + origin);
        }

    }

}

/*
    suspend fun validateServletRequest(request:ServerHttpRequest, options: ValidateRequestOptions)
{
    validateRequest(
            request.headers["X-${config.cookieNamePrefix}-csrf"]?.first(),
            request.cookies[cookieName.csrf]?.first()?.value,
        request.headers["Origin"]?.first(),
        options
        )
}

    private suspend fun validateRequest(
        csrfHeader: String?,
        csrfCookie: String?,
        origin: String?,
        options: ValidateRequestOptions
)
{

    if (options.requireTrustedOrigin)
    {
        validateOrigin(origin)
    }

    if (options.requireCsrfHeader)
    {
        validateCSRFToken(csrfCookie, csrfHeader)
    }
}

    private suspend fun validateCSRFToken(csrfCookie: String?, csrfHeader: String?)
{
    if (csrfCookie == null)
    {
        throw UnauthorizedException("No CSRF cookie was supplied in a POST request")
    }

    val decryptedCsrf = cookieEncrypter.decryptValueFromCookie(csrfCookie)
    if (decryptedCsrf != csrfHeader)
    {
        throw UnauthorizedException("The CSRF header did not match the CSRF cookie in a POST request")
    }
}

    private fun validateOrigin(origin: String?)
    {
        if (origin == null || !config.trustedWebOrigins.contains(origin))
        {
            throw UnauthorizedException("The call is from an untrusted web origin: $origin")
        }
    }


}

class ValidateRequestOptions(
        val requireTrustedOrigin: Boolean = true,
        val requireCsrfHeader: Boolean = true
)
*/

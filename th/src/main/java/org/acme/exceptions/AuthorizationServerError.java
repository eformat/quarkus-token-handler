package org.acme.exceptions;

import org.jboss.resteasy.reactive.RestResponse;

public class AuthorizationServerError extends BaseException {

    public AuthorizationServerError(String message) {
        super(message, null, RestResponse.StatusCode.FORBIDDEN, "authorization_error");
    }
}

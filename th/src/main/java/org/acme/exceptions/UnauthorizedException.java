package org.acme.exceptions;

import org.jboss.resteasy.reactive.RestResponse;

public class UnauthorizedException extends BaseException {

    public UnauthorizedException(String message) {
        super(message, null, RestResponse.StatusCode.FORBIDDEN, "unauthorized_request");
    }

}

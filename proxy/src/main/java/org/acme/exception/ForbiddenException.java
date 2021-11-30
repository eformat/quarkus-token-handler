package org.acme.exceptions;

import org.jboss.resteasy.reactive.RestResponse;

public class ForbiddenException extends BaseException {

    public ForbiddenException(String message) {
        super(message, null, RestResponse.StatusCode.FORBIDDEN, "forbidden_request");
    }

}

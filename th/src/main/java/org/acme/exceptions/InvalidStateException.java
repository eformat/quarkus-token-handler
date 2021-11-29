package org.acme.exceptions;

import org.jboss.resteasy.reactive.RestResponse;

public class InvalidStateException extends BaseException {

    public InvalidStateException(String message) {
        super(message, null, RestResponse.StatusCode.BAD_REQUEST, "invalid_state");
    }
}

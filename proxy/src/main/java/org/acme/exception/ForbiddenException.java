package org.acme.exception;

public class ForbiddenException extends BaseException {

    public ForbiddenException(String message) {
        super(message, null, 403, "forbidden_request");
    }

}

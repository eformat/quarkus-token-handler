package org.acme.exceptions;

public class BaseException extends RuntimeException {

    private int statusCode;
    private String code;

    public BaseException(String message, Throwable cause, int statusCode, String code) {
        super(message, cause);
        this.statusCode = statusCode;
        this.code = code;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getCode() {
        return code;
    }

}

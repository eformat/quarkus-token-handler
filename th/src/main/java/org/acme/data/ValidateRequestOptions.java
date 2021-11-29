package org.acme.data;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public class ValidateRequestOptions {
    public boolean requireTrustedOrigin;
    public boolean requireCsrfHeader;

    public ValidateRequestOptions(boolean requireTrustedOrigin, boolean requireCsrfHeader) {
        this.requireTrustedOrigin = requireTrustedOrigin;
        this.requireCsrfHeader = requireCsrfHeader;
    }
}

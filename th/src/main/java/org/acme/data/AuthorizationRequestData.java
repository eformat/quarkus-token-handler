package org.acme.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.quarkus.runtime.annotations.RegisterForReflection;
import io.vertx.core.json.JsonObject;

@RegisterForReflection
public class AuthorizationRequestData {
    @JsonProperty("code_verifier")
    private String codeVerifier;
    @JsonProperty("state")
    private String state;
    @JsonIgnore
    private JsonObject url;

    public AuthorizationRequestData() {
    }

    public AuthorizationRequestData(String codeVerifier, String state, JsonObject url) {
        this.codeVerifier = codeVerifier;
        this.state = state;
        this.url = url;
    }

    public String getCodeVerifier() {
        return codeVerifier;
    }

    public void setCodeVerifier(String codeVerifier) {
        this.codeVerifier = codeVerifier;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public JsonObject getUrl() {
        return url;
    }

    public void setUrl(JsonObject url) {
        this.url = url;
    }

}

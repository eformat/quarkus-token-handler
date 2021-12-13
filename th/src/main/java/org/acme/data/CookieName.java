package org.acme.data;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class CookieName {

    @ConfigProperty(name = "cookieDomain")
    String cookieDomain;

    @ConfigProperty(name = "cookieNamePrefix")
    String cookieNamePrefix;

    // out temporary login
    public String LOGIN () {
        return cookieNamePrefix + "-login";
    }

    // id token from openid
    public String ID () {
        return cookieNamePrefix + "-id";
    }

    // usually bearer access token
    public String ACCESS () {
        return cookieNamePrefix + "-at";
    }

    // usually refresh token
    public String REFRESH() {
        return cookieNamePrefix + "-auth";
    }

    // cross site request forgery token
    public String CSRF () {
        return cookieNamePrefix + "-csrf";
    }

    // Cookie Domain
    public String DOMAIN() { return cookieDomain; }
}

package org.acme.data;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class CookieName {

    @ConfigProperty(name = "cookieNamePrefix")
    String cookieNamePrefix;

    public String LOGIN () {
        return cookieNamePrefix + "-login";
    }

}

package org.cybersecurity.config.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class CrlConfig {

    private final String crlBaseUrl;

    public CrlConfig(
            @Value("${pki.crl.base-url}") String crlBaseUrl
    ) {
        this.crlBaseUrl = crlBaseUrl;
    }

    public String getCrlBaseUrl() {
        return crlBaseUrl;
    }


}

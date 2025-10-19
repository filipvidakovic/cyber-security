package org.cybersecurity.config.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class CrlConfig {

    private final String crlBaseUrl;
    private final String crlFolder;

    public CrlConfig(
            @Value("${pki.crl.base-url}") String crlBaseUrl,
            @Value("${pki.crl.folder}") String crlFolder
    ) {
        this.crlBaseUrl = crlBaseUrl;
        this.crlFolder = crlFolder;
    }

    public String getCrlBaseUrl() {
        return crlBaseUrl;
    }

    public String getCrlFolder() {
        return crlFolder;
    }
}

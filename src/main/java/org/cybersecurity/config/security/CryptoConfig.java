package org.cybersecurity.config.security;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class CryptoConfig {
    @Value("${pki.crl.base-url}")
    private static String crlBaseUrl;

    public static String getCrlBaseUrl() {
        return crlBaseUrl;
    }
}
package org.cybersecurity.crypto;

import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

@Component
public class KeyStoreService {
    public byte[] toPkcs12(PrivateKey priv,
                           X509Certificate cert,
                           List<X509Certificate> chain,
                           char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        X509Certificate[] arr = chain == null ? new X509Certificate[]{cert}
                : chain.toArray(new X509Certificate[0]);
        ks.setKeyEntry("key", priv, password, arr);
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            ks.store(bos, password);
            return bos.toByteArray();
        }
    }
}

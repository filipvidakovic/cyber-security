package org.cybersecurity.services.pki;

import lombok.RequiredArgsConstructor;
import org.cybersecurity.crypto.KeyStoreService;
import org.cybersecurity.crypto.KeyVaultService;
import org.cybersecurity.model.pki.CertificateEntity;
import org.cybersecurity.model.pki.PrivateKeyBlob;
import org.cybersecurity.repositories.pki.CertificateRepository;
import org.cybersecurity.repositories.pki.PrivateKeyRepository;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.springframework.transaction.annotation.Transactional;


@Service
@RequiredArgsConstructor
public class DownloadService {

    private final CertificateRepository certRepo;
    private final PrivateKeyRepository keyRepo;
    private final KeyStoreService keyStores;   // za .p12
    private final KeyVaultService vault;       // za AES-GCM decrypt

    /**
     * Kreira PKCS#12 fajl za dati certId (leaf cert + privatni ključ + chain ako postoji).
     */
    @Transactional(readOnly = true)
    public byte[] downloadP12(Long certId, char[] password) throws Exception {
        // 1) Učitaj cert zapis iz baze
        CertificateEntity leafE = certRepo.findById(certId).orElseThrow();

        // 2) Parse PEM → X509Certificate
        X509Certificate leaf = parseCert(leafE.getPem());

        // 3) Učitaj i dešifruj privatni ključ
        PrivateKeyBlob keyBlob = keyRepo.findByCertId(certId)
                .orElseThrow(() -> new IllegalStateException("No private key stored for certId=" + certId));
        byte[] pkcs8 = vault.decrypt(keyBlob.getEncBlob(), aad(certId));

        KeyFactory kf = KeyFactory.getInstance(keyBlob.getAlgo(), "BC");
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));

        // 4) Sastavi lanac (leaf → issuer → ...), ako postoje roditelji u bazi
        List<X509Certificate> chain = buildChain(leafE);

        // 5) Spakuj u PKCS#12 i vrati bytes
        return keyStores.toPkcs12(priv, leaf, chain, password);
    }

    /** Pokuša da izgradi chain: [issuer, issuer-of-issuer, ...] (leaf se dodaje u toPkcs12 posebno). */
    private List<X509Certificate> buildChain(CertificateEntity current) throws Exception {
        List<X509Certificate> chain = new ArrayList<>();
        Long issuerId = current.getIssuerId();
        while (issuerId != null) {
            CertificateEntity issuer = certRepo.findById(issuerId).orElse(null);
            if (issuer == null) break;
            chain.add(parseCert(issuer.getPem()));
            // Ako je root (issuer nema dalje izdavaoca), stajemo
            if (issuer.getIssuerId() == null) break;
            issuerId = issuer.getIssuerId();
        }
        return chain;
    }

    /** Jednostavan PEM → X509 parser (BC). */
    private static X509Certificate parseCert(String pem) throws Exception {
        String b64 = pem.replaceAll("-----\\w+ CERTIFICATE-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(b64);
        var holder = new org.bouncycastle.cert.X509CertificateHolder(der);
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(holder);
    }

    /** AAD = certId (8 bajtova) — mora biti isto kao u CaService.saveKey() */
    private static byte[] aad(Long id) {
        return java.nio.ByteBuffer.allocate(8).putLong(id).array();
    }
}

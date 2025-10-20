package org.cybersecurity.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemReader;
import org.cybersecurity.config.security.CrlConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Component
public class CryptoUtil {
    private final CrlConfig crlConfig;

    @Autowired
    public CryptoUtil(CrlConfig crlConfig) {
        this.crlConfig = crlConfig;
    }

    static { Security.addProvider(new BouncyCastleProvider()); }

    public KeyPair genRsa(int bits) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(bits);
        return kpg.generateKeyPair();
    }

    public X509Certificate selfSignedCa(
            KeyPair kp,
            X500Name subject,
            Duration ttl,
            Map<String, String> extensions, Long issuerId
    ) throws Exception {
        Instant now = Instant.now();
        BigInteger serial = new BigInteger(64, new SecureRandom());

        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                subject, serial,
                Date.from(now.minusSeconds(60)),
                Date.from(now.plus(ttl)),
                subject, kp.getPublic()
        );

        // ---- Policy validation & null-safety
        extensions = sanitizeExtensions(extensions);
        validateExtensions(extensions, /*isCa*/ true);

        // ---- BasicConstraints (critical): add if user didn’t
        if (!extensions.containsKey(Extension.basicConstraints.getId())) {
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        }

        // ---- KeyUsage (critical): add if user didn’t
        if (!extensions.containsKey(Extension.keyUsage.getId())) {
            b.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }

        // ---- SKI/AKI (non-critical): guard duplicates
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        if (!extensions.containsKey(Extension.subjectKeyIdentifier.getId())) {
            b.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(spki));
        }
        if (!extensions.containsKey(Extension.authorityKeyIdentifier.getId())) {
            b.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(spki));
        }

        // ---- CRL DP (non-critical)
        addRootCrlDistributionPoint(b,serial);
        
        // ---- Apply user extensions (after guards)
        ExtensionUtil.apply(b, extensions, /*isCa*/ true);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(kp.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(signer));
    }

    public X509Certificate signChild(PublicKey subjectPub,
                                     X500Name subject,
                                     X509Certificate issuerCert,
                                     PrivateKey issuerKey,
                                     boolean isCa,
                                     Duration ttl,
                                     Long issuerId,
                                     Map<String, String> extensions) throws Exception {
        Instant now = Instant.now();
        BigInteger serial = new BigInteger(64, new SecureRandom());
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuerCert, serial,
                Date.from(now.minusSeconds(60)),
                Date.from(now.plus(ttl)),
                subject, subjectPub);

        // ---- Policy validation & null-safety
        extensions = sanitizeExtensions(extensions);
        validateExtensions(extensions, isCa);

        // ---- BasicConstraints (critical)
        if (!extensions.containsKey(Extension.basicConstraints.getId())) {
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        }

        // ---- KeyUsage (critical)
        if (!extensions.containsKey(Extension.keyUsage.getId())) {
            boolean isEc = "EC".equalsIgnoreCase(subjectPub.getAlgorithm());
            int ku = isCa
                    ? (KeyUsage.keyCertSign | KeyUsage.cRLSign)
                    : (isEc ? KeyUsage.digitalSignature
                            : (KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(ku));
        }

        // ---- SKI/AKI (non-critical)
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        SubjectPublicKeyInfo childSpki = SubjectPublicKeyInfo.getInstance(subjectPub.getEncoded());
        SubjectPublicKeyInfo issuerSpki = SubjectPublicKeyInfo.getInstance(issuerCert.getPublicKey().getEncoded());
        if (!extensions.containsKey(Extension.subjectKeyIdentifier.getId())) {
            b.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(childSpki));
        }
        if (!extensions.containsKey(Extension.authorityKeyIdentifier.getId())) {
            b.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuerSpki));
        }

        // ---- CRL DP (non-critical)
        addCrlDistributionPoint(b, issuerId);

        // ---- Apply user extensions (after guards)
        ExtensionUtil.apply(b, extensions, isCa);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issuerKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(signer));
    }

    public PKCS10CertificationRequest parseCsr(byte[] pem) throws IOException {
        try (PemReader r = new PemReader(new InputStreamReader(new ByteArrayInputStream(pem)))) {
            return new PKCS10CertificationRequest(r.readPemObject().getContent());
        }
    }

    public static String toPem(X509Certificate cert) throws Exception {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
    }

    // ====================== helpers (safety) ======================

    private static Map<String, String> sanitizeExtensions(Map<String, String> extensions) {
        if (extensions == null || extensions.isEmpty()) return new java.util.HashMap<>();
        // Trim values; drop empties
        Map<String, String> out = new java.util.HashMap<>();
        for (var e : extensions.entrySet()) {
            String v = e.getValue() == null ? "" : e.getValue().trim();
            if (!v.isEmpty()) out.put(e.getKey(), v);
        }
        return out;
    }

    /**
     * Enforce policy before applying user-provided extensions.
     * - EE cannot request keyCertSign/cRLSign or BasicConstraints CA:true
     * - (Policy choice) Disallow EKU on CA (common practice)
     */
    private static void validateExtensions(Map<String, String> extensions, boolean isCa) {
        String ku = extensions.get(Extension.keyUsage.getId());
        String bc = extensions.get(Extension.basicConstraints.getId());

        if (!isCa) {
            if (ku != null) {
                String l = ku.toLowerCase();
                if (l.contains("keycertsign") || l.contains("crlsign")) {
                    throw new IllegalArgumentException("End-entity certificate cannot have keyCertSign/cRLSign in KeyUsage.");
                }
            }
            if (bc != null && bc.toLowerCase().contains("ca:true")) {
                throw new IllegalArgumentException("End-entity certificate cannot set BasicConstraints CA:true.");
            }
        }
    }

    private void addCrlDistributionPoint(JcaX509v3CertificateBuilder builder, Long issuerId) throws Exception {
        String crlUrl = crlConfig.getCrlBaseUrl() + "ca_" + issuerId;

        DistributionPointName distPointName = new DistributionPointName(
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl))
        );

        CRLDistPoint crlDistPoint = new CRLDistPoint(
                new DistributionPoint[] {
                        new DistributionPoint(distPointName, null, null)
                }
        );
        builder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);
        System.out.println("Added CRL DP for CA: " + crlUrl);

    }

    private void addRootCrlDistributionPoint(JcaX509v3CertificateBuilder builder, BigInteger serial) throws Exception {
        String crlUrl = crlConfig.getCrlBaseUrl() + "root_" + serial.toString(16);

        DistributionPointName distPointName = new DistributionPointName(
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl))
        );

        CRLDistPoint crlDistPoint = new CRLDistPoint(
                new DistributionPoint[] {
                        new DistributionPoint(distPointName, null, null)
                }
        );

        builder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);

        System.out.println("Added CRL DP for ROOT: " + crlUrl);
    }


}

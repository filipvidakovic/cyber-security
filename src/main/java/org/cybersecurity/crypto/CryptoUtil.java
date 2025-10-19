package org.cybersecurity.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
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


@Component
public class CryptoUtil {
    private CrlConfig crlConfig;

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

    public X509Certificate selfSignedCa(KeyPair kp, X500Name subject, Duration ttl) throws Exception {
        Instant now = Instant.now();
        BigInteger serial = new BigInteger(64, new SecureRandom());
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                subject, serial,
                Date.from(now.minusSeconds(60)),
                Date.from(now.plus(ttl)),
                subject, kp.getPublic());

        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        String crl = crlConfig.getCrlBaseUrl() + "root_" + serial.toString(16) + ".crl";

        DistributionPointName distPointName = new DistributionPointName(
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crl))
        );
        CRLDistPoint crlDistPoint = new CRLDistPoint(new DistributionPoint[] {
                new DistributionPoint(distPointName, null, null)
        });
        b.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(signer));
    }

    public X509Certificate signChild(PublicKey subjectPub,
                                     X500Name subject,
                                     X509Certificate issuerCert,
                                     PrivateKey issuerKey,
                                     boolean isCa,
                                     Duration ttl, Long issuerId) throws Exception {
        Instant now = Instant.now();
        BigInteger serial = new BigInteger(64, new SecureRandom());
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuerCert, serial,
                Date.from(now.minusSeconds(60)),
                Date.from(now.plus(ttl)),
                subject, subjectPub);

        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        int ku = isCa ? (KeyUsage.keyCertSign | KeyUsage.cRLSign)
                : (KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        b.addExtension(Extension.keyUsage, true, new KeyUsage(ku));

        String crl = crlConfig.getCrlBaseUrl() + "ca_" + issuerId.toString() + ".crl";

        DistributionPointName distPointName = new DistributionPointName(
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crl))
        );
        CRLDistPoint crlDistPoint = new CRLDistPoint(new DistributionPoint[] {
                new DistributionPoint(distPointName, null, null)
        });

        b.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);

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
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";    }
}

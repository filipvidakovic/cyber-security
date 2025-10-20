package org.cybersecurity.services.pki;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cybersecurity.crypto.CryptoUtil;
import org.cybersecurity.crypto.KeyVaultService;
import org.cybersecurity.model.pki.CertificateEntity;
import org.cybersecurity.model.pki.PrivateKeyBlob;
import org.cybersecurity.repositories.pki.CertificateRepository;
import org.cybersecurity.repositories.pki.PrivateKeyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class CaService {
    private final CryptoUtil crypto;
    private final KeyVaultService vault;
    private final CertificateRepository certRepo;
    private final PrivateKeyRepository keyRepo;

    @Transactional
    public Long createRoot(String cn, Duration ttl, String ownerEmail, Map<String,String> extensions) throws Exception {
        System.out.println("Creating root certificate for " + cn);
        System.out.println(LocalDateTime.now());
        KeyPair kp = crypto.genRsa(3072);
        System.out.println(LocalDateTime.now());
        X509Certificate root = crypto.selfSignedCa(kp, new X500Name(cn), ttl, extensions,null);
        System.out.println(LocalDateTime.now());
        Long certId = saveCert(root, "ROOT", null, getOrgId(cn), ownerEmail);
        System.out.println(LocalDateTime.now());
        saveKey(certId, kp.getPrivate(), 3072);
        System.out.println(LocalDateTime.now());
        System.out.println("Root CA created with ID=" + certId);
        return certId;
    }

    @Transactional
    public Long createIntermediate(Long issuerId, String cn, Duration ttl, String ownerEmail, Map<String,String> extensions) throws Exception {
        assertIssuerIsValid(issuerId);
        CertificateEntity issuer = certRepo.findById(issuerId).orElseThrow();
        validateChain(issuer);
        String orgId = getOrgId(cn);
        Instant max = issuer.getNotAfter();
        if (Instant.now().plus(ttl).isAfter(max)) throw new IllegalArgumentException("EE TTL exceeds issuer validity");
        // asserts that the organisations are the same if the issuer is CA_USER
        if (issuer.getType().equals("INT") && !issuer.getOrgId().equalsIgnoreCase(orgId)){
            throw new IllegalArgumentException("Issuer " + issuerId + " does not match orgId " + orgId);
        }
        X509Certificate issuerCert = Pem.parseCert(issuer.getPem());
        PrivateKey issuerKey = loadIssuerPriv(issuerId);
        KeyPair kp = crypto.genRsa(2048);
        X509Certificate child = crypto.signChild(kp.getPublic(),
                new X500Name(cn), issuerCert, issuerKey, true, ttl, issuerId,  extensions);
        Long certId = saveCert(child, "INT", issuerId, orgId, ownerEmail);
        saveKey(certId, kp.getPrivate(), 2048);

        System.out.println("Intermediate CA created with ID=" + certId);

        return certId;
    }

    private Long saveCert(X509Certificate c, String type, Long issuerId, String orgId, String ownerEmail) throws Exception {
        CertificateEntity e = new CertificateEntity();
        e.setType(type);
        e.setSubjectDn(c.getSubjectX500Principal().getName());
        e.setIssuerDn(c.getIssuerX500Principal().getName());
        e.setSerialHex(c.getSerialNumber().toString(16));
        e.setNotBefore(c.getNotBefore().toInstant());
        e.setNotAfter(c.getNotAfter().toInstant());
        e.setPem(CryptoUtil.toPem(c));
        System.out.println("Saving certificate with pem" + e.getPem());
        e.setIssuerId(issuerId);
        e.setStatus("VALID");
        e.setOrgId(orgId);
        e.setOwnerEmail(ownerEmail);
        return certRepo.save(e).getId();
    }

    private void saveKey(Long certId, PrivateKey priv, int size) throws Exception {
        byte[] pkcs8 = priv.getEncoded();
        byte[] blob = vault.encrypt(pkcs8, aad(certId));
        PrivateKeyBlob b = new PrivateKeyBlob();
        b.setCertId(certId); b.setAlgo(priv.getAlgorithm()); b.setKeySize(size); b.setEncBlob(blob);
        keyRepo.save(b);
    }
    @Transactional(readOnly = true)
    public PrivateKey loadIssuerPriv(Long issuerId) throws Exception {
        var cert = certRepo.findById(issuerId)
                .orElseThrow(() -> new IllegalArgumentException("Issuer certificate not found: " + issuerId));

        if ("REVOKED".equalsIgnoreCase(cert.getStatus())) {
            throw new IllegalStateException("Private key for revoked certificate (ID=" + issuerId + ") must not be used.");
        }

        var blob = keyRepo.findByCertId(issuerId).orElseThrow();
        byte[] pkcs8 = vault.decrypt(blob.getEncBlob(), aad(issuerId));
        KeyFactory kf = KeyFactory.getInstance(blob.getAlgo(), "BC");
        return kf.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(pkcs8));
    }

    private byte[] aad(Long id){
        return java.nio.ByteBuffer.allocate(8).putLong(id).array();
    }

    private void assertIssuerIsValid(Long issuerId) {
        CertificateEntity issuer = certRepo.findById(issuerId)
                .orElseThrow(() -> new IllegalArgumentException("Issuer not found: " + issuerId));

        // Only ROOT or INT can issue
        if ("EE".equalsIgnoreCase(issuer.getType())) {
            throw new IllegalArgumentException("Issuer is not a CA (issuerId=" + issuerId + ")");
        }
    }

    private String getOrgId(String cn){
        X500Name x500Name = new X500Name(cn);
        RDN[] orgRdns = x500Name.getRDNs(BCStyle.O);
        String orgId = (orgRdns.length > 0) ? orgRdns[0].getFirst().getValue().toString() : null;
        return orgId;
    }

    // Mali helper za PEM → X509
//    static class Pem {
//        static X509Certificate parseCert(String pem) throws Exception {
//            System.out.println(pem);
//            String b64 = pem.replaceAll("-----\\w+-----", "")
//                    .replaceAll("\\s", "");
//            System.out.println(b64);
//            byte[] der = java.util.Base64.getDecoder().decode(b64);
//            var holder = new org.bouncycastle.cert.X509CertificateHolder(der);
//            return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
//                    .setProvider("BC").getCertificate(holder);
//        }
//    }
    static class Pem {
        static X509Certificate parseCert(String pem) throws Exception {
            if (pem == null || pem.isBlank()) {
                throw new IllegalArgumentException("Empty PEM input");
            }

            // 🔹 1. Normalizuj oznake bez razmaka (BEGINCERTIFICATE → BEGIN CERTIFICATE)
            pem = pem.replaceAll("-----BEGINCERTIFICATE-----", "-----BEGIN CERTIFICATE-----")
                    .replaceAll("-----ENDCERTIFICATE-----", "-----END CERTIFICATE-----");

            // 🔹 2. Nađi prvi validan blok (ako ih ima više)
            int start = pem.indexOf("-----BEGIN CERTIFICATE-----");
            int end = pem.indexOf("-----END CERTIFICATE-----");
            if (start == -1 || end == -1 || end <= start) {
                throw new IllegalArgumentException("No valid PEM block found in input");
            }

            // 🔹 3. Izdvoji samo Base64 sadržaj između BEGIN i END
            String b64 = pem.substring(start + "-----BEGIN CERTIFICATE-----".length(), end);
            b64 = b64.replaceAll("\\s+", ""); // ukloni sve praznine, nove redove itd.

            // 🔹 4. Validiraj Base64 (ako nije validan, odmah baci grešku)
            byte[] der;
            try {
                der = Base64.getDecoder().decode(b64);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid Base64 content in PEM", e);
            }

            // 🔹 5. Parsiraj pomoću BouncyCastle-a
            var holder = new org.bouncycastle.cert.X509CertificateHolder(der);
            return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(holder);
        }
    }


    private void validateChain(CertificateEntity leaf) throws Exception {
        CertificateEntity current = leaf;
        X509Certificate prevCert = null; // za proveru potpisa prethodnog

        while (current != null) {
            X509Certificate cert = Pem.parseCert(current.getPem());

            // check if the cert is expired
            cert.checkValidity();

            // check if the cert is revoked
            if ("REVOKED".equalsIgnoreCase(current.getStatus())) {
                throw new IllegalStateException("Certificate " + current.getId() + " is revoked");
            }

            // check if the cert signature is valid
            if (prevCert != null) {
                try {
                    prevCert.verify(cert.getPublicKey()); // prevCert je issuer
                } catch (Exception e) {
                    throw new IllegalStateException("Certificate " + prevCert.getSerialNumber() +
                            " failed signature verification for child " + cert.getSerialNumber(), e);
                }
            }

            if (current.getIssuerId() == null) break;

            prevCert = cert;
            Long id = current.getIssuerId();
            current = certRepo.findById(id)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Issuer not found for certId=" + id));
        }
    }


}

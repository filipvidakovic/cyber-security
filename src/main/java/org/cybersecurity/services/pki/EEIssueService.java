package org.cybersecurity.services.pki;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cybersecurity.crypto.CryptoUtil;
import org.cybersecurity.crypto.KeyVaultService;
import org.cybersecurity.model.pki.CertificateEntity;
import org.cybersecurity.model.pki.PrivateKeyBlob;
import org.cybersecurity.repositories.pki.CertificateRepository;
import org.cybersecurity.repositories.pki.PrivateKeyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class EEIssueService {
    private final CryptoUtil crypto;
    private final KeyVaultService vault;
    private final CertificateRepository certRepo;
    private final PrivateKeyRepository keyRepo;

    @Transactional
    public Long issueAutogen(Long issuerId, String cn, Duration ttl, boolean storePrivKey) throws Exception {
        assertIssuerIsCA(issuerId);
        CertificateEntity issuer = certRepo.findById(issuerId).orElseThrow();
        validateChain(issuer);
        X509Certificate issuerCert = CaService.Pem.parseCert(issuer.getPem());
        PrivateKey issuerKey = loadIssuerPriv(issuerId);

        Instant max = issuer.getNotAfter();
        if (Instant.now().plus(ttl).isAfter(max)) throw new IllegalArgumentException("EE TTL exceeds issuer validity");
        String orgId = getOrgId(cn);
        // asserts that the organisations are the same if the issuer is CA_USER
        if (issuer.getType().equals("INT") && !issuer.getOrgId().equalsIgnoreCase(orgId)){
            throw new IllegalArgumentException("Issuer " + issuerId + " does not match orgId " + orgId);
        }

        KeyPair kp = crypto.genRsa(3072);
        X509Certificate ee = crypto.signChild(kp.getPublic(), new X500Name(cn),
                issuerCert, issuerKey, false, ttl);
        Long id = saveCert(ee, "EE", issuerId, getOrgId(cn));
        if (storePrivKey) saveKey(id, kp.getPrivate(), 3072);
        return id;
    }

    @Transactional
    public Long issueFromCsr(Long issuerId, byte[] csrPem, Duration ttl) throws Exception {
        assertIssuerIsCA(issuerId);
        CertificateEntity issuer = certRepo.findById(issuerId).orElseThrow();
        validateChain(issuer);
        X509Certificate issuerCert = CaService.Pem.parseCert(issuer.getPem());
        PrivateKey issuerKey = loadIssuerPriv(issuerId);

        Instant max = issuer.getNotAfter();
        if (Instant.now().plus(ttl).isAfter(max)) throw new IllegalArgumentException("EE TTL exceeds issuer validity");
        PKCS10CertificationRequest csr = crypto.parseCsr(csrPem);
        var spki = csr.getSubjectPublicKeyInfo();
        PublicKey pub = KeyFactory.getInstance("RSA", "BC")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(spki.getEncoded()));

        String orgId = getOrgId(csr.getSubject().toString());
        // asserts that the organisations are the same if the issuer is CA_USER
        if (issuer.getType().equals("INT") && !issuer.getOrgId().equalsIgnoreCase(orgId)){
            throw new IllegalArgumentException("Issuer " + issuerId + " does not match orgId " + orgId);
        }

        X509Certificate ee = crypto.signChild(pub, csr.getSubject(), issuerCert, issuerKey, false, ttl);
        return saveCert(ee, "EE", issuerId, orgId);
    }


    private Long saveCert(X509Certificate c, String type, Long issuerId, String orgId) throws Exception {
        CertificateEntity e = new CertificateEntity();
        e.setType(type);
        e.setSubjectDn(c.getSubjectX500Principal().getName());
        e.setIssuerDn(c.getIssuerX500Principal().getName());
        e.setSerialHex(c.getSerialNumber().toString(16));
        e.setNotBefore(c.getNotBefore().toInstant());
        e.setNotAfter(c.getNotAfter().toInstant());
        e.setPem(CryptoUtil.toPem(c));
        e.setIssuerId(issuerId);
        e.setStatus("VALID");
        e.setOrgId(orgId);
        return certRepo.save(e).getId();
    }

    private void saveKey(Long certId, PrivateKey priv, int size) throws Exception {
        byte[] pkcs8 = priv.getEncoded();
        byte[] blob = vault.encrypt(pkcs8, aad(certId));
        PrivateKeyBlob b = new PrivateKeyBlob();
        b.setCertId(certId); b.setAlgo(priv.getAlgorithm()); b.setKeySize(size); b.setEncBlob(blob);
        keyRepo.save(b);
    }

    private PrivateKey loadIssuerPriv(Long issuerId) throws Exception {
        var blob = keyRepo.findByCertId(issuerId).orElseThrow();
        byte[] pkcs8 = vault.decrypt(blob.getEncBlob(), aad(issuerId));
        KeyFactory kf = KeyFactory.getInstance(blob.getAlgo(), "BC");
        return kf.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(pkcs8));
    }

    private void assertIssuerIsCA(Long issuerId) {
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

    private void validateChain(CertificateEntity leaf) throws Exception {
        CertificateEntity current = leaf;
        X509Certificate prevCert = null; // za proveru potpisa prethodnog

        while (current != null) {
            X509Certificate cert = CaService.Pem.parseCert(current.getPem());

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

    private byte[] aad(Long id){
        return java.nio.ByteBuffer.allocate(8).putLong(id).array();
    }
}

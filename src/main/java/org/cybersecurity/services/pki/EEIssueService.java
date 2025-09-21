package org.cybersecurity.services.pki;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
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
        CertificateEntity issuer = certRepo.findById(issuerId).orElseThrow();
        ensureIssuerValid(issuer, ttl);
        X509Certificate issuerCert = CaService.Pem.parseCert(issuer.getPem());
        PrivateKey issuerKey = loadIssuerPriv(issuerId);

        KeyPair kp = crypto.genRsa(3072);
        X509Certificate ee = crypto.signChild(kp.getPublic(), new X500Name("CN="+cn),
                issuerCert, issuerKey, false, ttl);
        Long id = saveCert(ee, "EE", issuerId);
        if (storePrivKey) saveKey(id, kp.getPrivate(), 3072);
        return id;
    }

    @Transactional
    public Long issueFromCsr(Long issuerId, byte[] csrPem, Duration ttl) throws Exception {
        CertificateEntity issuer = certRepo.findById(issuerId).orElseThrow();
        ensureIssuerValid(issuer, ttl);
        X509Certificate issuerCert = CaService.Pem.parseCert(issuer.getPem());
        PrivateKey issuerKey = loadIssuerPriv(issuerId);

        PKCS10CertificationRequest csr = crypto.parseCsr(csrPem);
        var spki = csr.getSubjectPublicKeyInfo();
        PublicKey pub = KeyFactory.getInstance("RSA", "BC")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(spki.getEncoded()));
        X509Certificate ee = crypto.signChild(pub, csr.getSubject(), issuerCert, issuerKey, false, ttl);
        return saveCert(ee, "EE", issuerId);
    }

    private void ensureIssuerValid(CertificateEntity issuer, Duration ttl) {
        if (!"VALID".equals(issuer.getStatus())) throw new IllegalStateException("Issuer not VALID");
        Instant max = issuer.getNotAfter();
        if (Instant.now().plus(ttl).isAfter(max)) throw new IllegalArgumentException("EE TTL exceeds issuer validity");
    }

    private Long saveCert(X509Certificate c, String type, Long issuerId) throws Exception {
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

    private byte[] aad(Long id){
        return java.nio.ByteBuffer.allocate(8).putLong(id).array();
    }
}

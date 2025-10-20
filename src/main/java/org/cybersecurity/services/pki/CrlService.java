package org.cybersecurity.services.pki;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cybersecurity.model.pki.CertificateEntity;
import org.cybersecurity.repositories.pki.CertificateRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class CrlService {

    private final CertificateRepository certRepo;
    private final CaService caService;


    @Transactional(readOnly = true)
    public byte[] generateCrl(Long issuerId) throws Exception {
        CertificateEntity issuer = certRepo.findById(issuerId)
                .orElseThrow(() -> new IllegalArgumentException("Issuer not found: " + issuerId));

        PrivateKey issuerPrivateKey = caService.loadIssuerPriv(issuerId);
        if (issuerPrivateKey == null) {
            throw new IllegalStateException("No private key found for issuer " + issuer.getSubjectDn());
        }

        X500Name issuerName = new X500Name(issuer.getSubjectDn());
        Date now = new Date();
        Date nextUpdate = Date.from(Instant.now().plusSeconds(7 * 24 * 3600));

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerName, now);
        crlBuilder.setNextUpdate(nextUpdate);

        List<CertificateEntity> revokedCerts = certRepo.findByIssuerIdAndStatus(issuerId, "REVOKED");
        Set<Integer> allowedReasons = Set.of(1, 3, 4, 5, 9);

        for (CertificateEntity cert : revokedCerts) {
            BigInteger serial = new BigInteger(cert.getSerialHex(), 16);
            Date revocationDate = Date.from(
                    cert.getRevocationDate() != null ? cert.getRevocationDate() : Instant.now()
            );

            Integer reasonCode = cert.getRevocationReasonCode();
            if (reasonCode != null && allowedReasons.contains(reasonCode)) {
                crlBuilder.addCRLEntry(serial, revocationDate, reasonCode);
            } else {
                crlBuilder.addCRLEntry(serial, revocationDate,0);
            }
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(issuerPrivateKey);

        X509CRLHolder crlHolder = crlBuilder.build(signer);
        X509CRL crl = new JcaX509CRLConverter()
                .setProvider("BC")
                .getCRL(crlHolder);

        System.out.println("Generated CRL for issuer " + issuer.getSubjectDn() +
                " (" + revokedCerts.size() + " revoked entries)");
        return crl.getEncoded();
    }

    @Transactional(readOnly = true)
    public byte[] generateRootCrl(String serialHex) throws Exception {
        CertificateEntity rootCert = certRepo.findBySerialHex(serialHex)
                .orElseThrow(() -> new IllegalArgumentException("Root certificate not found for serialHex: " + serialHex));

        if (rootCert.getIssuerId() != null) {
            throw new IllegalStateException("Certificate with serialHex " + serialHex + " is not a root CA.");
        }

        PrivateKey rootPrivateKey = caService.loadIssuerPriv(rootCert.getId());
        if (rootPrivateKey == null) {
            throw new IllegalStateException("No private key found for root CA: " + rootCert.getSubjectDn());
        }

        X500Name issuerName = new X500Name(rootCert.getSubjectDn());
        Date now = new Date();
        Date nextUpdate = Date.from(Instant.now().plusSeconds(7 * 24 * 3600));

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerName, now);
        crlBuilder.setNextUpdate(nextUpdate);

        List<CertificateEntity> revokedCerts = certRepo.findByIssuerIdAndStatus(rootCert.getId(), "REVOKED");
        Set<Integer> allowedReasons = Set.of(1, 3, 4, 5, 9);

        for (CertificateEntity cert : revokedCerts) {
            BigInteger revokedSerial = new BigInteger(cert.getSerialHex(), 16);
            Date revocationDate = Date.from(
                    cert.getRevocationDate() != null ? cert.getRevocationDate() : Instant.now()
            );

            Integer reasonCode = cert.getRevocationReasonCode();
            if (reasonCode != null && allowedReasons.contains(reasonCode)) {
                crlBuilder.addCRLEntry(revokedSerial, revocationDate, reasonCode);
            } else {
                crlBuilder.addCRLEntry(revokedSerial, revocationDate, 0);
            }
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(rootPrivateKey);

        X509CRLHolder crlHolder = crlBuilder.build(signer);
        X509CRL crl = new JcaX509CRLConverter()
                .setProvider("BC")
                .getCRL(crlHolder);

        System.out.println("Generated ROOT CRL for serialHex " + serialHex +
                " (" + revokedCerts.size() + " revoked entries)");

        return crl.getEncoded();
    }



}

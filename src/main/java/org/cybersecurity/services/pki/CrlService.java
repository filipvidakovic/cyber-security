package org.cybersecurity.services.pki;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cybersecurity.model.pki.CertificateEntity;
import org.cybersecurity.repositories.pki.CertificateRepository;
import org.springframework.stereotype.Service;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
public class CrlService {

    private final CertificateRepository certRepo;
    private final CaService caService; // To get issuer private key
     private final String crlDir = "../../crls/";

    /**
     * Build a CRL for the given CA certificate.
     *
     * @param issuerId The CA certificate
     * @return X509CRL object
     * @throws Exception on error
     */
    public X509CRL buildCrl(Long issuerId) throws Exception {
         CertificateEntity issuerEntity = certRepo.findById(issuerId)
                .orElseThrow(() -> new IllegalArgumentException("Issuer not found: " + issuerId));

        X509Certificate issuerCert = CaService.Pem.parseCert(issuerEntity.getPem());


        Instant now = Instant.now();

        // Build CRL
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(
                new JcaX509CertificateHolder(issuerCert).getSubject(),
                Date.from(now)
        );

        // Set next update
        crlBuilder.setNextUpdate(Date.from(now.plusSeconds(7 * 24 * 3600))); // e.g., 1 week

        // Add revoked certificates issued by this CA
        List<CertificateEntity> revokedCerts = certRepo.findByIssuerIdAndStatus(issuerId, "REVOKED");
        for (CertificateEntity c : revokedCerts) {
            CRLReason reason = c.getRevocationReasonCode() != null
                    ? CRLReason.lookup(c.getRevocationReasonCode())
                    : CRLReason.lookup(CRLReason.unspecified);

            crlBuilder.addCRLEntry(
                    new BigInteger(c.getSerialHex(), 16),
                    Date.from(c.getRevocationDate() != null ? c.getRevocationDate() : now),
                    reason.getValue().intValue()
            );
        }

        // Sign CRL with issuer private key
        PrivateKey issuerKey = caService.loadIssuerPriv(issuerId);
        var signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        X509CRL crl = new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));
        // Write CRL to file
        try (FileOutputStream fos = new FileOutputStream(crlDir + issuerCert.getSerialNumber().toString(16) + ".crl")) {
            fos.write(crl.getEncoded());
        }

        System.out.println("CRL updated for issuer " + issuerId + ", file written to " + crlDir);

        return crl;
    }
}

package org.cybersecurity.services.pki;

import lombok.RequiredArgsConstructor;
import org.cybersecurity.dto.pki.CertificateDTO;
import org.cybersecurity.dto.pki.IssuerDTO;
import org.cybersecurity.model.pki.CertificateEntity;
import org.cybersecurity.model.user.BaseUser;
import org.cybersecurity.repositories.pki.CertificateRepository;
import org.cybersecurity.repositories.pki.PrivateKeyRepository;
import org.cybersecurity.services.user.UserService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class CertificateService {

    private final CertificateRepository certRepo;
    private final PrivateKeyRepository keyRepo;
    private final CrlService crlService;
    private final UserService userService;

    /**
     * Revoke a certificate and all its descendants recursively.
     *
     * @param certId     ID of the certificate to revoke
     * @param reasonCode X.509 CRLReason code
     * @throws Exception if certificate not found or already revoked
     */
    @Transactional
    public void revokeCertificate(Long certId, int reasonCode) throws Exception {
        CertificateEntity cert = certRepo.findById(certId)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + certId));

        if (cert.getNotAfter().isBefore(Instant.now())) {
            System.out.println("Certificate " + certId + " is expired, skipping revocation.");
            return;
        }
        // If already revoked, skip
        if (!"REVOKED".equalsIgnoreCase(cert.getStatus())) {
            cert.setStatus("REVOKED");
            cert.setRevocationDate(Instant.now());
            cert.setRevocationReasonCode(reasonCode);
            certRepo.save(cert);

            // Disable or delete the private key
            keyRepo.findByCertId(certId).ifPresent(keyBlob -> {
                keyBlob.setEncBlob(null);
                keyRepo.save(keyBlob);
            });

            System.out.println("Certificate " + certId + " revoked for reason code " + reasonCode);

            if (cert.getIssuerId() != null) {
                crlService.buildCrl(cert.getIssuerId());
                System.out.println("CRL updated for issuer " + cert.getIssuerId());
            }
        }

        // Revoke all children recursively
        List<CertificateEntity> children = certRepo.findByIssuerId(certId);
        for (CertificateEntity child : children) {
            revokeCertificate(child.getId(), reasonCode);
        }
    }

    public List<CertificateDTO> getAllCertificates() {
        return certRepo.findAll()
                .stream()
                .map(c -> new CertificateDTO(
                        c.getId(),
                        c.getType(),
                        c.getSubjectDn(),
                        c.getIssuerDn(),
                        c.getSerialHex(),
                        c.getNotBefore(),
                        c.getNotAfter(),
                        c.getStatus(),
                        c.getRevocationDate(),
                        c.getRevocationReasonCode(),
                        c.getOrgId()
                ))
                .toList();
    }
    public List<CertificateDTO> getUserCertificates() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        return certRepo.findDTOsByOwnerEmail(email);
    }

    public List<CertificateDTO> getCaUserCertificates() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        BaseUser user = userService.getUserByEmail(email);
        return certRepo.findDTOsByOrgId(user.getOrganization());
    }

    public List<IssuerDTO> getPossibleIssuers() {
        return certRepo.findIssuerSummaries(List.of("ROOT", "INT"));
    }




}

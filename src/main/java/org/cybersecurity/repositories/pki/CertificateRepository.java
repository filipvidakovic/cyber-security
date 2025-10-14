package org.cybersecurity.repositories.pki;

import org.cybersecurity.model.pki.CertificateEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CertificateRepository extends JpaRepository<CertificateEntity, Long> {
     List<CertificateEntity> findByIssuerId(Long issuerId);
     List<CertificateEntity> findByIssuerIdAndStatus(Long issuerId, String status);
     Optional<CertificateEntity> findBySerialHex(String serialHex);
}


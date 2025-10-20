package org.cybersecurity.repositories.pki;

import org.bouncycastle.cert.cmp.CertificateStatus;
import org.cybersecurity.dto.pki.CertificateDTO;
import org.cybersecurity.dto.pki.IssuerDTO;
import org.cybersecurity.model.pki.CertificateEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface CertificateRepository extends JpaRepository<CertificateEntity, Long> {
     List<CertificateEntity> findByIssuerId(Long issuerId);

     List<CertificateEntity> findByIssuerIdAndStatus(Long issuerId, String status);

     Optional<CertificateEntity> findBySerialHex(String serialHex);

     @Query("SELECT new org.cybersecurity.dto.pki.CertificateDTO(" +
             "c.id, c.type, c.subjectDn, c.issuerDn, c.serialHex, " +
             "c.notBefore, c.notAfter, c.status, c.revocationDate, " +
             "c.revocationReasonCode, c.orgId) " +
             "FROM CertificateEntity c WHERE c.ownerEmail = :ownerEmail")
     List<CertificateDTO> findDTOsByOwnerEmail(@Param("ownerEmail") String ownerEmail);

     @Query("SELECT new org.cybersecurity.dto.pki.CertificateDTO(" +
             "c.id, c.type, c.subjectDn, c.issuerDn, c.serialHex, " +
             "c.notBefore, c.notAfter, c.status, c.revocationDate, " +
             "c.revocationReasonCode, c.orgId) " +
             "FROM CertificateEntity c WHERE c.orgId = :orgId")
     List<CertificateDTO> findDTOsByOrgId(@Param("orgId") String orgId);

     @Query("SELECT new org.cybersecurity.dto.pki.IssuerDTO(c.id, c.subjectDn, c.type) " +
             "FROM CertificateEntity c " +
             "WHERE c.type IN :types " +
             "AND c.status = 'VALID' " +
             "AND c.notAfter > CURRENT_TIMESTAMP")
     List<IssuerDTO> findIssuerSummaries(@Param("types") List<String> types);

}


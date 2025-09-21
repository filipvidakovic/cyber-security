package org.cybersecurity.repositories.pki;

import org.cybersecurity.model.pki.CertificateEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CertificateRepository extends JpaRepository<CertificateEntity, Long> { }

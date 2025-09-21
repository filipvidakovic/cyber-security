package org.cybersecurity.repositories.pki;

import org.cybersecurity.model.pki.PrivateKeyBlob;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PrivateKeyRepository extends JpaRepository<PrivateKeyBlob, Long> {
    Optional<PrivateKeyBlob> findByCertId(Long certId);
}

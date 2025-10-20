package org.cybersecurity.repositories.template;

import org.cybersecurity.model.template.CertificateTemplate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TemplateRepository extends JpaRepository<CertificateTemplate, Long> {

    boolean existsByName(String name);
}
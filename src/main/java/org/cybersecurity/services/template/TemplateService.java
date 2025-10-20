package org.cybersecurity.services.template;

import org.cybersecurity.model.template.CertificateTemplate;
import org.cybersecurity.repositories.template.TemplateRepository;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@Transactional
public class TemplateService {

    private final TemplateRepository templateRepository;

    public TemplateService(TemplateRepository templateRepository) {
        this.templateRepository = templateRepository;
    }

    public List<CertificateTemplate> getAllTemplates() {
        return templateRepository.findAll();
    }

    public Optional<CertificateTemplate> getTemplateById(Long id) {
        return templateRepository.findById(id);
    }

    public CertificateTemplate createTemplate(CertificateTemplate template) {
        if (templateRepository.existsByName(template.getName())) {
            throw new IllegalArgumentException("Template with the same name already exists.");
        }
        return templateRepository.save(template);
    }

    public CertificateTemplate updateTemplate(Long id, CertificateTemplate updatedTemplate) {
        CertificateTemplate existing = templateRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Template not found with id " + id));

        existing.setName(updatedTemplate.getName());
        existing.setIssuerId(updatedTemplate.getIssuerId());
        existing.setCnRegex(updatedTemplate.getCnRegex());
        existing.setSanRegex(updatedTemplate.getSanRegex());
        existing.setMaxTtlDays(updatedTemplate.getMaxTtlDays());
        existing.setKeyUsage(updatedTemplate.getKeyUsage());
        existing.setExtendedKeyUsage(updatedTemplate.getExtendedKeyUsage());

        return templateRepository.save(existing);
    }

    public void deleteTemplate(Long id) {
        if (!templateRepository.existsById(id)) {
            throw new IllegalArgumentException("Template not found with id " + id);
        }
        templateRepository.deleteById(id);
    }
}

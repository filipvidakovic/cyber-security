package org.cybersecurity.controllers.template;

import org.cybersecurity.model.template.CertificateTemplate;
import org.cybersecurity.services.template.TemplateService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/templates")
public class TemplateController {

    private final TemplateService service;

    public TemplateController(TemplateService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<List<CertificateTemplate>> listTemplates() {
        return ResponseEntity.ok(service.getAllTemplates());
    }

    @GetMapping("/{id}")
    public ResponseEntity<CertificateTemplate> getTemplateById(@PathVariable Long id) {
        return service.getTemplateById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<CertificateTemplate> createTemplate(@RequestBody CertificateTemplate dto) {
        CertificateTemplate created = service.createTemplate(dto);
        return ResponseEntity.ok(created);
    }

    @PutMapping("/{id}")
    public ResponseEntity<CertificateTemplate> updateTemplate(@PathVariable Long id, @RequestBody CertificateTemplate dto) {
        try {
            CertificateTemplate updated = service.updateTemplate(id, dto);
            return ResponseEntity.ok(updated);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteTemplate(@PathVariable Long id) {
        try {
            service.deleteTemplate(id);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        }
    }
}

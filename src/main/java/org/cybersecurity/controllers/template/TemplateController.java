package org.cybersecurity.controllers.template;

import org.cybersecurity.model.template.CertificateTemplate;
import org.cybersecurity.services.template.TemplateService;
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
    public List<CertificateTemplate> listTemplates() {
        return service.getAllTemplates();
    }

    @PostMapping
    public CertificateTemplate createTemplate(@RequestBody CertificateTemplate dto) {
        return service.createTemplate(dto);
    }
}

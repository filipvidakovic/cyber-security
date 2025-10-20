package org.cybersecurity.controllers.template;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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

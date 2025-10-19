package org.cybersecurity.dto.pki;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class IssuerDTO {
    private Long id;
    private String subjectDn;
    private String type;
}

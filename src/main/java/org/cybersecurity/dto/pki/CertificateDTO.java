package org.cybersecurity.dto.pki;

import java.time.Instant;

public class CertificateDTO {
    private Long id;
    private String type; // ROOT, INT, EE
    private String subjectDn;
    private String issuerDn;
    private String serialHex;
    private Instant notBefore;
    private Instant notAfter;
    private String status; // VALID, REVOKED
    private Instant revocationDate;
    private Integer revocationReasonCode;
    private String orgId;

    // --- Constructors ---
    public CertificateDTO() {}

    public CertificateDTO(Long id, String type, String subjectDn, String issuerDn,
                          String serialHex, Instant notBefore, Instant notAfter,
                          String status, Instant revocationDate,
                          Integer revocationReasonCode, String orgId) {
        this.id = id;
        this.type = type;
        this.subjectDn = subjectDn;
        this.issuerDn = issuerDn;
        this.serialHex = serialHex;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.status = status;
        this.revocationDate = revocationDate;
        this.revocationReasonCode = revocationReasonCode;
        this.orgId = orgId;
    }

    // --- Getters & Setters ---
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String getSubjectDn() { return subjectDn; }
    public void setSubjectDn(String subjectDn) { this.subjectDn = subjectDn; }

    public String getIssuerDn() { return issuerDn; }
    public void setIssuerDn(String issuerDn) { this.issuerDn = issuerDn; }

    public String getSerialHex() { return serialHex; }
    public void setSerialHex(String serialHex) { this.serialHex = serialHex; }

    public Instant getNotBefore() { return notBefore; }
    public void setNotBefore(Instant notBefore) { this.notBefore = notBefore; }

    public Instant getNotAfter() { return notAfter; }
    public void setNotAfter(Instant notAfter) { this.notAfter = notAfter; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public Instant getRevocationDate() { return revocationDate; }
    public void setRevocationDate(Instant revocationDate) { this.revocationDate = revocationDate; }

    public Integer getRevocationReasonCode() { return revocationReasonCode; }
    public void setRevocationReasonCode(Integer revocationReasonCode) { this.revocationReasonCode = revocationReasonCode; }

    public String getOrgId() { return orgId; }
    public void setOrgId(String orgId) { this.orgId = orgId; }
}

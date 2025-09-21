package org.cybersecurity.model.pki;

import jakarta.persistence.*;
import lombok.Getter; import lombok.Setter;

import java.time.Instant;

@Getter @Setter
@Entity @Table(name = "certificates")
public class CertificateEntity {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable=false) private String type; // ROOT, INT, EE
    @Column(nullable=false, length=1024) private String subjectDn;
    @Column(nullable=false, length=1024) private String issuerDn;
    @Column(nullable=false) private String serialHex;
    @Column(nullable=false) private Instant notBefore;
    @Column(nullable=false) private Instant notAfter;
    @Column(nullable=false) private String status; // VALID, REVOKED
    @Lob @Column(nullable=false) private String pem;

    private Long issuerId;
    private Long orgId;

    @PrePersist void onCreate(){ if (status==null) status = "VALID"; }
}

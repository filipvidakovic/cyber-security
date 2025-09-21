package org.cybersecurity.model.pki;

import jakarta.persistence.*;
import lombok.Getter; import lombok.Setter;

@Getter @Setter
@Entity @Table(name="private_keys")
public class PrivateKeyBlob {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable=false) private Long certId;
    @Column(nullable=false) private String algo;   // RSA / EC
    @Column(nullable=false) private Integer keySize;

    @Lob @Column(nullable=false)
    private byte[] encBlob; // AES-GCM blob (IV+tag+ct pakovano)
}

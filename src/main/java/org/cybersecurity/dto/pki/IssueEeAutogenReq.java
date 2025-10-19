package org.cybersecurity.dto.pki;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class IssueEeAutogenReq {
    @NotNull
    private Long issuerId;

    @NotBlank
    private String cn;

    @Min(1)
    private int ttlDays;

    private boolean storePrivateKey;

    private Map<String,String> extensions;

}

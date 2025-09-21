package org.cybersecurity.dto.pki;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class CreateIntReq {
    @NotNull
    private Long issuerId;

    @NotBlank
    private String cn;

    @Min(1)
    private int ttlDays;

}

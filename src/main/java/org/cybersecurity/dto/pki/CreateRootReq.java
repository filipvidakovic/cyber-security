package org.cybersecurity.dto.pki;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class CreateRootReq {
    @NotBlank
    private String cn;

    @Min(1)
    private int ttlDays;
}

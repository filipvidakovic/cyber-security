package org.cybersecurity.dto.auth;

import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.cybersecurity.model.user.UserRole;
import org.hibernate.validator.constraints.Length;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RegisterUserDto {
    @NotBlank(message = "Email is required")
    @Email(message = "Email is invalid")
    private String email;
    @NotBlank(message = "Password is required")
    @Length(min = 8, max = 64, message = "Password must be at between 6 and 32 characters")
    private String password;
    @Enumerated(EnumType.STRING)
    private UserRole userRole;
    @NotBlank(message = "First name is required")
    @Length(min = 1, max = 100, message = "First name must be between 1 and 100 characters")
    private String firstName;
    @NotBlank(message = "First name is required")
    @Length(min = 1, max = 100, message = "First name must be between 1 and 100 characters")
    private String lastName;
    @NotBlank(message = "First name is required")
    @Length(min = 1, max = 100, message = "First name must be between 1 and 100 characters")
    private String organization;
}

package com.innowise.authentication.service.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record RegistrationRequestDto(
        @Email
        @NotNull
        String email,

        @NotNull
        @Size(min = 8)
        String password
) {
}

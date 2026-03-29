package com.innowise.authentication.service.dto;

import jakarta.validation.constraints.*;

import java.time.LocalDate;

public record RegistrationRequestDto(
        @Email
        @NotNull
        String email,

        @NotNull
        @Size(min = 8)
        String password,

        @NotBlank
        @Size(min = 2, max = 50)
        String name,

        @NotBlank
        @Size(min = 2, max = 50)
        String surname,

        @NotNull
        @Past
        LocalDate birthDate
) {
}

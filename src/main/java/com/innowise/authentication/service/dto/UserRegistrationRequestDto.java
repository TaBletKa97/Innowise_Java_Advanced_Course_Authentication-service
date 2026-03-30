package com.innowise.authentication.service.dto;

import java.time.LocalDate;

public record UserRegistrationRequestDto(
        Long id,
        String name,
        String surname,
        LocalDate birthDate,
        String email,
        boolean active
) {
}

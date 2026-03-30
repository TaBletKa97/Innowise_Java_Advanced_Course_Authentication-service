package com.innowise.authentication.service.dto;

import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalDateTime;

public record UserResponseDto(
        Long id,
        String name,
        String surname,
        LocalDate birthDate,
        String email,
        boolean active,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) implements Serializable {
}

package com.innowise.authentication.service.dto;

import com.innowise.authentication.repository.entity.Role;

public record RegistrationResponseDto(
        Long id,
        String email,
        Role role
) {
}

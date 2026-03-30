package com.innowise.authentication.service.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequestDto(
        @NotBlank
        String email,
        @NotBlank
        String password
) {
}

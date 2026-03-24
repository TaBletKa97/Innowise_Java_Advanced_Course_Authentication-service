package com.innowise.authentication.service.dto;

public record LoginRequestDto(
        String email,
        String password
) {
}

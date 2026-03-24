package com.innowise.authentication.service;

import com.innowise.authentication.service.dto.LoginRequestDto;
import com.innowise.authentication.service.dto.RegistrationRequestDto;
import com.innowise.authentication.service.dto.RegistrationResponseDto;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Map;

public interface AuthService {

    RegistrationResponseDto register(RegistrationRequestDto request);

    Map<String, String> login(LoginRequestDto request);

    Boolean validateToken(HttpServletRequest request);

    Map<String, String> refresh(Map<String, String> tokens);
}

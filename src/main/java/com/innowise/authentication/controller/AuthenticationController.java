package com.innowise.authentication.controller;

import com.innowise.authentication.service.AuthService;
import com.innowise.authentication.service.dto.LoginRequestDto;
import com.innowise.authentication.service.dto.RegistrationRequestDto;
import com.innowise.authentication.service.dto.RegistrationResponseDto;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthService authService;

    @GetMapping("/validate")
    public ResponseEntity<Boolean> validateToken(@Autowired HttpServletRequest request) {
        return ResponseEntity.ok(authService.validateToken(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refreshToken(
            @RequestBody Map<String, String> tokens) {
        return ResponseEntity.ok(authService.refresh(tokens));
    }

    @PostMapping("/register")
    public ResponseEntity<RegistrationResponseDto> register(
            @RequestBody @Validated RegistrationRequestDto request) {
        RegistrationResponseDto responseDto = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(responseDto);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(
            @RequestBody @Validated LoginRequestDto request) {
        return ResponseEntity.ok(authService.login(request));
    }
}

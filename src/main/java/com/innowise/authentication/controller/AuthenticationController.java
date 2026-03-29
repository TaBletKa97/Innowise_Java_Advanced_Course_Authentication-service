package com.innowise.authentication.controller;

import com.innowise.authentication.service.AuthService;
import com.innowise.authentication.service.dto.LoginRequestDto;
import com.innowise.authentication.service.dto.RegistrationRequestDto;
import com.innowise.authentication.service.dto.RegistrationResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

import static com.innowise.authentication.utils.Constants.BEARER;
import static com.innowise.authentication.utils.Constants.HEADER_AUTHORIZATION;

/**
 * Controller for handling authentication operations.
 */
@RestController
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthService authService;

    /**
     * Registers a new user with the provided registration details.
     *
     * @param request The registration data transfer object containing user details
     * such as email, password, name, surname, and birthdate.
     * @return A ResponseEntity containing the response data transfer object with
     * the created user's id, email, and role.
     */
    @PostMapping("/register")
    public ResponseEntity<RegistrationResponseDto> register(
            @RequestBody @Validated RegistrationRequestDto request) {
        RegistrationResponseDto responseDto = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(responseDto);
    }

    /**
     * Logs in a user with the provided credentials.
     *
     * @param request The login data transfer object containing the user's email
     * and password.
     * @return A ResponseEntity containing a map with authentication tokens if
     * the credentials are valid, or error messages otherwise.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(
            @RequestBody @Validated LoginRequestDto request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * Logs out a user by invalidating their authentication token.
     *
     * @param header The HTTP header containing the authorization token.
     * Expected format is "Bearer <token>".
     * @return A ResponseEntity indicating the operation was successful.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader (HEADER_AUTHORIZATION) String header
    ) {
        String token = header.substring(BEARER.length());
        authService.logout(token);
        return ResponseEntity.ok().build();
    }

    /**
     * Validates a given authentication token.
     *
     * @param header The HTTP header containing the authorization token.
     * Expected format is "Bearer <token>".
     * @return A ResponseEntity containing a map with user id and user role
     * if token is valid, or error messages if not.
     */
    @GetMapping("/validate")
    public ResponseEntity<Map<String, String>> validateToken(
            @RequestHeader (HEADER_AUTHORIZATION) String header) {

        String token = header.substring(BEARER.length());

        return ResponseEntity.ok(authService.validateToken(token));
    }

    /**
     * Refreshes the authentication tokens for a user.
     *
     * @param tokens A map containing the current refresh token and access token.
     * @return A ResponseEntity containing a map with the new access token and
     * refresh token if successful, or error messages otherwise.
     */
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refreshToken(
            @RequestBody Map<String, String> tokens) {
        return ResponseEntity.ok(authService.refresh(tokens));
    }
}

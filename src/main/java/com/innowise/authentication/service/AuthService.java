package com.innowise.authentication.service;

import com.innowise.authentication.exceptions.BadCredentialsException;
import com.innowise.authentication.exceptions.RefreshTokenException;
import com.innowise.authentication.exceptions.RegistrationInUserserviceException;
import com.innowise.authentication.exceptions.UserAlreadyExistException;
import com.innowise.authentication.service.dto.LoginRequestDto;
import com.innowise.authentication.service.dto.RegistrationRequestDto;
import com.innowise.authentication.service.dto.RegistrationResponseDto;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Map;

/**
 * AuthService interface defines methods for handling authentication and authorization operations.
 */
public interface AuthService {

    /**
     * Registers a new user.
     *
     * @param request The registration data transfer object containing user details
     * such as email, password, name, surname, and birthdate.
     * @return A {@link RegistrationResponseDto} containing the registered user's
     * ID, email, and role.
     * @throws UserAlreadyExistException If a user with the same email already exists.
     * @throws RegistrationInUserserviceException If there is an issue registering
     * the user in the external user service.
     */
    RegistrationResponseDto register(RegistrationRequestDto request);

    /**
     * Authenticates a user and returns access and refresh tokens.
     *
     * @param request The {@link LoginRequestDto} containing the user's email and password.
     * @return A {@code Map<String, String>} with keys "access_token" and "refresh_token",
     * containing the JWT tokens for accessing resources and refreshing them.
     * @throws BadCredentialsException If the provided credentials are invalid.
     * @throws UsernameNotFoundException If there is no user with provided email.
     */
    Map<String, String> login(LoginRequestDto request);

    /**
     * Validates the provided JWT token and returns a map containing claims such
     * as user ID and role.
     *
     * @param token The JWT token to validate.
     * @return A {@code Map<String, String>} containing claims, where keys are
     * "user_id" and "role".
     */
    Map<String, String> validateToken(String token);

    /**
     * Refreshes the access and refresh tokens.
     *
     * @param tokens A {@code Map<String, String>} containing "refreshToken" key
     * with the current refresh token value.
     * @return A {@code Map<String, String>} with keys "accessToken" and
     * "refreshToken", containing the refreshed JWT tokens.
     * @throws RefreshTokenException If the provided refresh token is invalid,
     * expired or has been revoked.
     */
    Map<String, String> refresh(Map<String, String> tokens);

    /**
     * Logs out a user by revoking their access token.
     *
     * @param token The JWT access token associated with the user to be logged out.
     */
    void logout(String token);
}

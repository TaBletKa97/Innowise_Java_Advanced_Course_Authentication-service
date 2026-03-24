package com.innowise.authentication.utils;

import com.innowise.authentication.repository.entity.Role;
import com.innowise.authentication.repository.entity.UserCredentials;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenUtilsTest {

    private JwtTokenUtils jwtTokenUtils;
    private UserCredentials credentials;

    @BeforeEach
    void setUp() {
        jwtTokenUtils = new JwtTokenUtils();

        credentials = new UserCredentials("test@mail.com", null, Role.USER);
        credentials.setId(1L);

        String secret = "super-secret-key-at-least-32-characters-long!!";
        ReflectionTestUtils.setField(jwtTokenUtils, "secret", secret);
        ReflectionTestUtils.setField(jwtTokenUtils, "jwtAccessLifetime", Duration.ofMinutes(15));
        ReflectionTestUtils.setField(jwtTokenUtils, "jwtRefreshLifetime", Duration.ofDays(30));

        ReflectionTestUtils.invokeMethod(jwtTokenUtils, "init");
    }

    @Test
    void generateAccessToken_ShouldCreateValidToken() {


        String token = jwtTokenUtils.generateAccessToken(credentials);

        assertNotNull(token);
        assertEquals("test@mail.com", jwtTokenUtils.getLogin(token));
        assertEquals("USER", jwtTokenUtils.getRole(token));
        assertEquals(1L, jwtTokenUtils.getUserId(token));
        assertTrue(jwtTokenUtils.validateJwtToken(token));
    }

    @Test
    void isValidRefreshToken_ShouldReturnTrueForRefreshToken() {
        String refreshToken = jwtTokenUtils.generateRefreshToken(credentials);

        boolean isValid = jwtTokenUtils.isValidRefreshToken(refreshToken);

        assertTrue(isValid);
    }

    @Test
    void isValidRefreshToken_ShouldReturnFalseForAccessToken() {
        String accessToken = jwtTokenUtils.generateAccessToken(credentials);

        boolean isValid = jwtTokenUtils.isValidRefreshToken(accessToken);

        assertFalse(isValid);
    }

    @Test
    void validateJwtToken_ShouldReturnFalseForInvalidToken() {
        String invalidToken = "eyJhbGciOiJIUzI1NiJ9.invalid.payload";

        boolean isValid = jwtTokenUtils.validateJwtToken(invalidToken);

        assertFalse(isValid);
    }
}

//git actions
package com.innowise.authentication.service;

import com.innowise.authentication.exceptions.BadCredentialsException;
import com.innowise.authentication.exceptions.RefreshTokenException;
import com.innowise.authentication.exceptions.UserAlreadyExistException;
import com.innowise.authentication.repository.UserCredentialsRepository;
import com.innowise.authentication.repository.entity.Role;
import com.innowise.authentication.repository.entity.UserCredentials;
import com.innowise.authentication.service.dto.LoginRequestDto;
import com.innowise.authentication.service.dto.RegistrationRequestDto;
import com.innowise.authentication.service.dto.RegistrationResponseDto;
import com.innowise.authentication.service.dto.mapper.CredentialsMapper;
import com.innowise.authentication.utils.JwtTokenUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.innowise.authentication.utils.Constants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    UserCredentialsRepository userRepository;

    @Mock
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Mock
    CredentialsMapper credentialsMapper;

    @Mock
    JwtTokenUtils jwtTokenUtils;

    @InjectMocks
    AuthServiceImpl authServiceImpl;

    @Test
    void registerNormalFlowTest() {
        final String username = "username";
        final String password = "password";
        final String encodedPass = "encodedPass";
        RegistrationRequestDto registrationRequestDto =
                new RegistrationRequestDto(username, password);
        var expectedResponse = new RegistrationResponseDto(1L, username, Role.USER);

        when(userRepository.existsByEmail(username)).thenReturn(false);
        when(bCryptPasswordEncoder.encode(password)).thenReturn(encodedPass);
        when(credentialsMapper.entityToResponse(any())).thenReturn(expectedResponse);

        authServiceImpl.register(registrationRequestDto);

        verify(userRepository).existsByEmail(username);
        verify(userRepository).saveAndFlush(any());
        verify(credentialsMapper).entityToResponse(any());
        verify(bCryptPasswordEncoder).encode(password);
    }

    @Test
    void registerThrowsUserAlreadyExistsException() {
        final String username = "username";
        final String password = "password";
        var registrationRequestDto = new RegistrationRequestDto(username, password);

        when(userRepository.existsByEmail(username)).thenReturn(true);

        assertThrows(UserAlreadyExistException.class, () ->
                authServiceImpl.register(registrationRequestDto));
    }

    @Test
    void login() {
        final String username = "username";
        final String password = "password";
        final String encodedPass = "encodedPass";
        final String accessToken = "accessToken";
        final String refreshToken = "refreshToken";
        final UserCredentials userCredentials =
                new UserCredentials(username, encodedPass, Role.USER);

        var requestDto = new LoginRequestDto(username, password);

        when(userRepository.findByEmail(username))
                .thenReturn(Optional.of(userCredentials));
        when(bCryptPasswordEncoder.matches(password, encodedPass)).thenReturn(true);
        when(jwtTokenUtils.generateAccessToken(any())).thenReturn(accessToken);
        when(jwtTokenUtils.generateRefreshToken(any())).thenReturn(refreshToken);

        Map<String, String> login = authServiceImpl.login(requestDto);

        verify(userRepository).findByEmail(username);
        verify(bCryptPasswordEncoder).matches(password, encodedPass);
        verify(jwtTokenUtils).generateAccessToken(userCredentials);
        verify(jwtTokenUtils).generateRefreshToken(userCredentials);

        assertEquals(accessToken, login.get("accessToken"));
        assertEquals(refreshToken, login.get("refreshToken"));
    }

    @Test
    void loginThrowsUsernameNotFoundException() {
        final String username = "username";
        final String password = "password";
        var requestDto = new LoginRequestDto(username, password);

        when(userRepository.findByEmail(username)).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () ->
                authServiceImpl.login(requestDto));
    }

    @Test
    void loginThrowsBadCredentialsException() {
        final String username = "username";
        final String password = "password";
        final String encodedPass = "encodedPass";
        var requestDto = new LoginRequestDto(username, password);
        var userCredentials = new UserCredentials(username, encodedPass, Role.USER);

        when(userRepository.findByEmail(username)).thenReturn(Optional.of(userCredentials));
        when(bCryptPasswordEncoder.matches(password, encodedPass)).thenReturn(false);

        assertThrows(BadCredentialsException.class, () ->
                authServiceImpl.login(requestDto));
    }


    @Test
    void validateTokenNormalFlow() {
        var request = new MockHttpServletRequest();
        String header = "Bearer token";
        request.addHeader(HEADER_AUTHORIZATION, header);

        when(jwtTokenUtils.validateJwtToken(any())).thenReturn(true);

        assertTrue(authServiceImpl.validateToken(request));
    }

    @Test
    void validateTokenNegativeScenario() {
        var request = new MockHttpServletRequest();

        assertFalse(authServiceImpl.validateToken(request));

        request.addHeader(HEADER_AUTHORIZATION, "");

        assertFalse(authServiceImpl.validateToken(request));
    }

    @Test
    void refresh() {
        final String oldAccessToken = "oldAccessToken";
        final String oldRefreshToken = "oldRefreshToken";
        final String accessToken = "accessToken";
        final String refreshToken = "refreshToken";

        Map<String, String> requestTokens = new HashMap<>();
        requestTokens.put(REFRESH_TOKEN, oldRefreshToken);
        requestTokens.put(ACCESS_TOKEN, oldAccessToken);

        when(jwtTokenUtils.isValidRefreshToken(any())).thenReturn(true);
        when(jwtTokenUtils.getLogin(any())).thenReturn("");
        when(userRepository.findByEmail(any())).thenReturn(Optional.of(new UserCredentials()));
        when(jwtTokenUtils.generateAccessToken(any())).thenReturn(accessToken);
        when(jwtTokenUtils.generateRefreshToken(any())).thenReturn(refreshToken);

        Map<String, String> refresh = authServiceImpl.refresh(requestTokens);
        assertEquals(accessToken, refresh.get(ACCESS_TOKEN));
        assertEquals(refreshToken, refresh.get(REFRESH_TOKEN));
    }

    @Test
    void refreshThrowsRefreshTokenException() {
        Map<String, String> requestTokens = new HashMap<>();

        assertThrows(RefreshTokenException.class, () -> authServiceImpl.refresh(requestTokens));

        requestTokens.put(REFRESH_TOKEN, "");
        when(jwtTokenUtils.isValidRefreshToken(any())).thenReturn(false);
        assertThrows(RefreshTokenException.class, () -> authServiceImpl.refresh(requestTokens));
    }
}
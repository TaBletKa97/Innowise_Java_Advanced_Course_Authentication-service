package com.innowise.authentication.service;

import com.innowise.authentication.exceptions.BadCredentialsException;
import com.innowise.authentication.exceptions.RefreshTokenException;
import com.innowise.authentication.exceptions.UserAlreadyExistException;
import com.innowise.authentication.external.UserHttpClient;
import com.innowise.authentication.repository.UserCredentialsRepository;
import com.innowise.authentication.repository.entity.Role;
import com.innowise.authentication.repository.entity.UserCredentials;
import com.innowise.authentication.service.dto.LoginRequestDto;
import com.innowise.authentication.service.dto.RegistrationRequestDto;
import com.innowise.authentication.service.dto.UserRegistrationRequestDto;
import com.innowise.authentication.service.dto.mapper.CredentialsMapper;
import com.innowise.authentication.utils.JwtTokenUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.innowise.authentication.utils.Constants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    UserCredentialsRepository userRepository;

    @Mock
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Mock
    JwtTokenUtils tokenUtils;

    @Mock
    CredentialsMapper mapper;

    @Mock
    UserHttpClient httpClient;

    @Mock
    RedisTemplate<String, String> redisTemplate;

    @Mock
    ValueOperations<String, String> valueOperations;

    @InjectMocks
    AuthServiceImpl authServiceImpl;


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
        when(tokenUtils.generateAccessToken(any())).thenReturn(accessToken);
        when(tokenUtils.generateRefreshToken(any())).thenReturn(refreshToken);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        Map<String, String> login = authServiceImpl.login(requestDto);

        verify(userRepository).findByEmail(username);
        verify(bCryptPasswordEncoder).matches(password, encodedPass);
        verify(tokenUtils).generateAccessToken(userCredentials);
        verify(tokenUtils).generateRefreshToken(userCredentials);

        assertEquals(accessToken, login.get("accessToken"));
        assertEquals(refreshToken, login.get("refreshToken"));
    }

    @Test
    void logoutRemovesRefreshToken() {
        String token = "validToken";
        String login = "user@example.com";

        when(tokenUtils.getLogin(any())).thenReturn(login);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.getAndDelete(REFRESH_TOKEN + login)).thenReturn("oldAccessToken");

        authServiceImpl.logout(token);

        verify(tokenUtils).getLogin(token);
        verify(valueOperations).getAndDelete(REFRESH_TOKEN + login);
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
        String token = "token";
        Long id = 1L;
        Role role = Role.USER;

        when(tokenUtils.getUserId(any())).thenReturn(id);
        when(tokenUtils.getRole(any())).thenReturn(role.toString());

        Map<String, String> claims = authServiceImpl.validateToken(token);

        assertTrue(claims.containsKey(USER_ID));
        assertTrue(claims.containsKey(USER_ROLE));
        assertEquals(String.valueOf(id), claims.get(USER_ID));
        assertEquals(role.toString(), claims.get(USER_ROLE));
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

        when(tokenUtils.isValidRefreshToken(any())).thenReturn(true);
        when(tokenUtils.getLogin(any())).thenReturn("");
        when(userRepository.findByEmail(any())).thenReturn(Optional.of(new UserCredentials()));
        when(tokenUtils.generateAccessToken(any())).thenReturn(accessToken);
        when(tokenUtils.generateRefreshToken(any())).thenReturn(refreshToken);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.getAndDelete(any())).thenReturn(oldAccessToken);

        Map<String, String> refresh = authServiceImpl.refresh(requestTokens);
        assertEquals(accessToken, refresh.get(ACCESS_TOKEN));
        assertEquals(refreshToken, refresh.get(REFRESH_TOKEN));
    }

    @Test
    void refreshThrowsRefreshTokenException() {
        Map<String, String> requestTokens = new HashMap<>();

        assertThrows(RefreshTokenException.class, () -> authServiceImpl.refresh(requestTokens));

        requestTokens.put(REFRESH_TOKEN, "");
        when(tokenUtils.isValidRefreshToken(any())).thenReturn(false);
        assertThrows(RefreshTokenException.class, () -> authServiceImpl.refresh(requestTokens));
    }

    @Test
    void registerThrowsUserAlreadyExistException() {
        final String email = "existing@example.com";
        final String password = "password";
        final String name = "John";
        final String surname = "Doe";
        final LocalDate birthDate = LocalDate.of(1990, 1, 1);
        final RegistrationRequestDto request = new RegistrationRequestDto(email, password, name, surname, birthDate);

        when(userRepository.existsByEmail(any())).thenReturn(true);

        assertThrows(UserAlreadyExistException.class, () -> authServiceImpl.register(request));
    }

    @Test
    void registerSuccessful() {
        final String email = "new@example.com";
        final String password = "password";
        final String name = "John";
        final String surname = "Doe";
        final LocalDate birthDate = LocalDate.of(1990, 1, 1);
        final UserCredentials credentials = new UserCredentials(email, password, Role.USER);
        credentials.setId(1L);
        final RegistrationRequestDto request =
                new RegistrationRequestDto(email, password, name, surname, birthDate);
        final UserRegistrationRequestDto userRegistrationRequestDto =
                new UserRegistrationRequestDto(1L, name, surname, birthDate, email, true);


        when(userRepository.existsByEmail(any())).thenReturn(false);
        when(userRepository.saveAndFlush(any())).thenReturn(credentials);
        when(mapper.prepareRequestPassword(any(), eq(request))).thenReturn(userRegistrationRequestDto);
        when(httpClient.createUser(any(UserRegistrationRequestDto.class))).thenReturn(null);
        when(mapper.entityToResponse(any())).thenReturn(null);

        authServiceImpl.register(request);

        verify(userRepository).existsByEmail(email);
        verify(userRepository).saveAndFlush(any(UserCredentials.class));
        verify(httpClient).createUser(userRegistrationRequestDto);
        verify(mapper).prepareRequestPassword(any(), any());
        verify(mapper).entityToResponse(any());
    }
}
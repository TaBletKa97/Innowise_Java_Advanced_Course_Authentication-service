package com.innowise.authentication.service;

import com.innowise.authentication.exceptions.BadCredentialsException;
import com.innowise.authentication.exceptions.RefreshTokenException;
import com.innowise.authentication.exceptions.RegistrationInUserserviceException;
import com.innowise.authentication.exceptions.UserAlreadyExistException;
import com.innowise.authentication.external.UserHttpClient;
import com.innowise.authentication.repository.UserCredentialsRepository;
import com.innowise.authentication.repository.entity.Role;
import com.innowise.authentication.repository.entity.UserCredentials;
import com.innowise.authentication.service.dto.*;
import com.innowise.authentication.service.dto.mapper.CredentialsMapper;
import com.innowise.authentication.utils.JwtTokenUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static com.innowise.authentication.utils.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class AuthServiceImpl implements AuthService {

    @Value("${jwt.refresh-lifetime}")
    private Duration jwtRefreshLifetime;

    private final UserCredentialsRepository repository;
    private final CredentialsMapper mapper;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtTokenUtils tokenUtils;
    private final UserHttpClient httpClient;
    private final RedisTemplate<String, String> redisTemplate;



    public RegistrationResponseDto register(RegistrationRequestDto request) {
        log.debug("Register request: {}", request);

        if (repository.existsByEmail(request.email())) {
            throw new UserAlreadyExistException(
                    String.format(USER_WITH_EMAIL_EXIST_MSG, request.email()));
        }

        UserCredentials credentials = new UserCredentials(
                request.email(),
                passwordEncoder.encode(request.password()),
                Role.USER
        );
        repository.saveAndFlush(credentials);

        UserResponseDto user;
        try {
            UserRegistrationRequestDto userServiceRequest =
                    mapper.prepareRequestPassword(credentials.getId(), request);
            log.debug("UserRegistrationRequestDto: {}", userServiceRequest);
            user = httpClient.createUser(userServiceRequest);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new RegistrationInUserserviceException();
        }

        log.debug("User {} has been registered in Auth-service", credentials);
        log.debug("User {} has been registered in User-service", user);

        return mapper.entityToResponse(credentials);
    }

    public Map<String, String> login(LoginRequestDto request) {
        log.debug("Login request: {}", request);

        UserCredentials userCredentials = repository.findByEmail(request.email())
                .orElseThrow(() -> new BadCredentialsException(USERNAME_NOT_FOUND_MSG));

        if (!userCredentials.getEmail().equals(request.email()) ||
                !passwordEncoder.matches(request.password(),
                        userCredentials.getPasswordHash())) {
            throw new BadCredentialsException(WRONG_CREDENTIALS_MSG);
        }

        String accessToken = tokenUtils.generateAccessToken(userCredentials);
        log.debug("Generated access token: {}", accessToken);
        String refreshToken = tokenUtils.generateRefreshToken(userCredentials);
        log.debug("Generated refresh token: {}", refreshToken);

        redisTemplate.opsForValue().set(
                REFRESH_TOKEN + userCredentials.getEmail(),
                refreshToken,
                jwtRefreshLifetime
        );

        Map<String, String> tokens = new HashMap<>();
        tokens.put(ACCESS_TOKEN, accessToken);
        tokens.put(REFRESH_TOKEN, refreshToken);

        return tokens;
    }

    public Map<String, String> validateToken(String token) {
        Map<String, String> claims = new HashMap<>();
        claims.put(USER_ID, String.valueOf(tokenUtils.getUserId(token)));
        claims.put(USER_ROLE, tokenUtils.getRole(token));

        return claims;
    }

    @Override
    public Map<String, String> refresh(Map<String, String> tokens) {
        if (!tokens.containsKey(REFRESH_TOKEN)) {
            throw new RefreshTokenException(REFRESH_TOKEN_ABSENCE_MSG);
        }
        if (!tokenUtils.isValidRefreshToken(tokens.get(REFRESH_TOKEN))) {
            throw new RefreshTokenException(REFRESH_TOKEN_NOT_VALID_MSG);
        }
        String login = tokenUtils.getLogin(tokens.get(REFRESH_TOKEN));

        String oldToken = redisTemplate.opsForValue()
                .getAndDelete(REFRESH_TOKEN + login);
        if (oldToken == null) {
            throw  new RefreshTokenException(USER_WAS_LOGGED_OUT_MSG);
        }

        UserCredentials userCredentials = repository.findByEmail(login)
                .orElseThrow(() -> new BadCredentialsException(USERNAME_NOT_FOUND_MSG));

        Map<String, String> response = new HashMap<>();
        String newAccessToken = tokenUtils.generateAccessToken(userCredentials);
        String newRefreshToken = tokenUtils.generateRefreshToken(userCredentials);
        response.put(ACCESS_TOKEN, newAccessToken);
        response.put(REFRESH_TOKEN, newRefreshToken);

        redisTemplate.opsForValue().set(REFRESH_TOKEN + login,
                newRefreshToken, jwtRefreshLifetime);

        return response;
    }

    @Override
    public void logout(String token) {
        String login = tokenUtils.getLogin(token);
        log.debug("Logout for user: {} with token {}", login, token);
        redisTemplate.opsForValue().getAndDelete(REFRESH_TOKEN + login);
    }
}

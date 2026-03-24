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
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

import static com.innowise.authentication.utils.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class AuthServiceImpl implements AuthService {

    private final UserCredentialsRepository repository;
    private final CredentialsMapper credentialsMapper;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtTokenUtils tokenUtils;

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

        log.debug("User {} has been registered", credentials);

        return credentialsMapper.entityToResponse(credentials);
    }


    public Map<String, String> login(LoginRequestDto request) {
        log.debug("Login request: {}", request);

        UserCredentials userCredentials = repository.findByEmail(request.email())
                .orElseThrow(() -> new UsernameNotFoundException(USERNAME_NOT_FOUND_MSG));

        if (!userCredentials.getEmail().equals(request.email()) ||
                !passwordEncoder.matches(request.password(), userCredentials.getPasswordHash())) {
            throw new BadCredentialsException(WRONG_CREDENTIALS_MSG);
        }

        String accessToken = tokenUtils.generateAccessToken(userCredentials);
        log.debug("Generated access token: {}", accessToken);
        String refreshToken = tokenUtils.generateRefreshToken(userCredentials);
        log.debug("Generated refresh token: {}", refreshToken);

        Map<String, String> tokens = new HashMap<>();
        tokens.put(ACCESS_TOKEN, accessToken);
        tokens.put(REFRESH_TOKEN, refreshToken);

        return tokens;
    }

    public Boolean validateToken(HttpServletRequest request) {
        String header = request.getHeader(HEADER_AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER)) {
            return false;
        }
        return tokenUtils.validateJwtToken(header.substring(BEARER.length()));
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
        UserCredentials userCredentials = repository.findByEmail(login).orElseThrow();

        Map<String, String> response = new HashMap<>();
        response.put(ACCESS_TOKEN, tokenUtils.generateAccessToken(userCredentials));
        response.put(REFRESH_TOKEN, tokenUtils.generateRefreshToken(userCredentials));
        return response;
    }
}

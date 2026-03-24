package com.innowise.authentication.utils;

import com.innowise.authentication.repository.entity.UserCredentials;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenUtils {

    private static final String TYPE = "type";
    private static final String ROLE = "role";
    private static final String ID = "id";
    private static final String VALIDATION_ERROR = "JWT validation error: {}";

    @Value("${JWT_SECRET}")
    private String secret;

    @Value("${jwt.access-lifetime}")
    private Duration jwtAccessLifetime;

    @Value("${jwt.refresh-lifetime}")
    private Duration jwtRefreshLifetime;

    private SecretKey key;

    @PostConstruct
    private void init() {
        this.key = Keys.hmacShaKeyFor(
                secret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(UserCredentials credentials) {
        return generateToken(credentials, jwtAccessLifetime, TokenType.ACCESS_TOKEN);
    }

    public String generateRefreshToken(UserCredentials credentials) {
        return generateToken(credentials, jwtRefreshLifetime, TokenType.REFRESH_TOKEN);
    }

    private String generateToken(UserCredentials credentials, Duration lifetime, TokenType tokenType) {
        final Date creationDate = new Date();
        final Date expirationDate = new Date(creationDate.getTime() + lifetime.toMillis());

        return Jwts.builder().claims()
                .subject(credentials.getEmail())
                .add(ID, credentials.getId())
                .add(ROLE, credentials.getRole().toString())
                .add(TYPE, tokenType.toString())
                .issuedAt(creationDate)
                .expiration(expirationDate)
                .and().signWith(key)
                .compact();
    }

    public Claims getClaimsFromToken(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateJwtToken(String token) {
        try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.debug(VALIDATION_ERROR, e.getMessage());
        }
        return false;
    }

    public boolean isValidRefreshToken(String token) {
        try {
            Claims claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
            return claims.get(TYPE).equals(TokenType.REFRESH_TOKEN.toString());
        } catch (JwtException | IllegalArgumentException e) {
            log.debug(VALIDATION_ERROR, e.getMessage());
        }
        return false;
    }

    public String getRole(String token) {
        return getClaimsFromToken(token).get(ROLE, String.class);
    }

    public String getLogin(String token) {
        return getClaimsFromToken(token).getSubject();
    }

    public Long getUserId(String token) {
        return getClaimsFromToken(token).get(ID, Long.class);
    }


    private enum TokenType {
        ACCESS_TOKEN,
        REFRESH_TOKEN;

        @Override
        public String toString() {
            return super.toString().toLowerCase();
        }
    }
}

package com.innowise.authentication.exceptions;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.Arrays;
import java.util.stream.Collectors;

@Log4j2
@ControllerAdvice
public class CommonExceptionHandler {
    private static final String LOGIN_AND_PASSWORD_ERROR = "Login or password is incorrect.";
    private static final String USER_EXIST_ERROR = "User already exist.";
    private static final String TOKEN_EXPIRED_ERROR = "Token has expired.";
    private static final String TOKEN_ERROR = "Token is invalid.";
    private static final String REGISTRATION_REQUIREMENT = "Email should be valid.\nPassword should be not less than 8 characters.";

    @ExceptionHandler
    public ResponseEntity<String> handleGeneralException(Exception e) {
       logError(e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
    }

    @ExceptionHandler
    public ResponseEntity<String> handleAuthenticationException(BadCredentialsException e) {
        logError(e);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(LOGIN_AND_PASSWORD_ERROR);
    }

    @ExceptionHandler
    public ResponseEntity<String> handleUserAlreadyExistException(UserAlreadyExistException e) {
        logError(e);
        return ResponseEntity.status(HttpStatus.CONFLICT).body(USER_EXIST_ERROR);
    }

    @ExceptionHandler
    public ResponseEntity<String> handleExpiredJwtException(ExpiredJwtException e) {
        logError(e);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(TOKEN_EXPIRED_ERROR);
    }

    @ExceptionHandler
    public ResponseEntity<String> handleExpiredJwtException(JwtException e) {
        logError(e);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(TOKEN_ERROR);
    }

    @ExceptionHandler
    public ResponseEntity<String> handleValidationException(MethodArgumentNotValidException e) {
        logError(e);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(REGISTRATION_REQUIREMENT);
    }

    private static void logError(Throwable e) {
        String stacktrace = Arrays.stream(e.getStackTrace())
                .map(String::valueOf)
                .collect(Collectors.joining("\n"));
        log.error("{}\n{}\n{}\n",e.getClass(), e.getMessage(), stacktrace);
    }


}

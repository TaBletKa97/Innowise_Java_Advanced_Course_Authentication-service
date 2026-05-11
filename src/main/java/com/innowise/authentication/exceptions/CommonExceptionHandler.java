package com.innowise.authentication.exceptions;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import static com.innowise.authentication.utils.Constants.TOKEN_ERROR;
import static com.innowise.authentication.utils.Constants.TOKEN_EXPIRED_ERROR;

@Log4j2
@ControllerAdvice
public class CommonExceptionHandler {
    private static final String LOGIN_AND_PASSWORD_ERROR = "Login or password is incorrect.";
    private static final String USER_EXIST_ERROR = "User already exist.";
    private static final String REGISTRATION_REQUIREMENT = "Email should be valid." +
            "\nPassword should be not less than 8 characters.";
    private static final String TRY_AGAIN_REQUEST = "\n Please, try again later.";

    @ExceptionHandler
    public ResponseEntity<String> handleGeneralException(Exception e) {
        log.error(e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(e.getMessage());
    }

    @ExceptionHandler
    public ResponseEntity<String> handleAuthenticationException(
            BadCredentialsException e) {
        log.error(e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(LOGIN_AND_PASSWORD_ERROR);
    }

    @ExceptionHandler
    public ResponseEntity<String> handleUserAlreadyExistException(
            UserAlreadyExistException e) {
        log.error(e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(USER_EXIST_ERROR);
    }

    @ExceptionHandler
    public ResponseEntity<String> handleExpiredJwtException(
            ExpiredJwtException e) {
        log.error(e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(TOKEN_EXPIRED_ERROR);
    }

    @ExceptionHandler
    public ResponseEntity<String> handleJwtException(JwtException e) {
        log.error(e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(TOKEN_ERROR);
    }

    @ExceptionHandler
    public ResponseEntity<String> handleValidationException(
            MethodArgumentNotValidException e) {
        log.error(e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(REGISTRATION_REQUIREMENT);
    }

    @ExceptionHandler
    public ResponseEntity<String> handleRegistrationInUserserviceException(
            RegistrationInUserserviceException e) {
        log.error(e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                .body(e.getMessage() + TRY_AGAIN_REQUEST);
    }

    @ExceptionHandler
    public ResponseEntity<String> handleMissingRequestHeaderException(
            MissingRequestHeaderException e) {
        log.error(e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(e.getMessage());
    }
}

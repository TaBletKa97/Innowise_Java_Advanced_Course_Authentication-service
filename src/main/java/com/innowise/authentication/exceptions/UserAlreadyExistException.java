package com.innowise.authentication.exceptions;

import lombok.extern.log4j.Log4j2;

@Log4j2
public class UserAlreadyExistException extends RuntimeException {

    public UserAlreadyExistException(String message) {
       super(message);
    }
}

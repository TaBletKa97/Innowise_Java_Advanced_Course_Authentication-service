package com.innowise.authentication.exceptions;

public class RegistrationInUserserviceException extends RuntimeException {
    public RegistrationInUserserviceException() {
        super("There was an error registering the user");
    }

    public RegistrationInUserserviceException(String message) {
        super(message);
    }
}

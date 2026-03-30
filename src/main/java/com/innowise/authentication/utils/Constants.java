package com.innowise.authentication.utils;

public class Constants {

    private Constants() {
    }

    public static final String BEARER = "Bearer ";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String WRONG_CREDENTIALS_MSG = "Login or password are incorrect.";
    public static final String USERNAME_NOT_FOUND_MSG = "Login or password are incorrect.";
    public static final String USER_WITH_EMAIL_EXIST_MSG = "User with email %s already exists";
    public static final String REFRESH_TOKEN_ABSENCE_MSG = "You should provide a refresh token.";
    public static final String REFRESH_TOKEN_NOT_VALID_MSG = "You should provide a valid refresh token.";
    public static final String USER_WAS_LOGGED_OUT_MSG = "User was logged out.";

    public static final String REFRESH_TOKEN = "refreshToken";
    public static final String ACCESS_TOKEN = "accessToken";


    public static final String USER_ID = "user_id";
    public static final String USER_ROLE = "role";
}

package com.innowise.authentication.external;

import com.innowise.authentication.service.dto.UserRegistrationRequestDto;
import com.innowise.authentication.service.dto.UserResponseDto;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;

@HttpExchange(
        accept = "application/json",
        contentType = "application/json",
        url = "${USER_SERVICE_URL}"
)
public interface UserHttpClient {

    @PostExchange("/users")
    UserResponseDto createUser(@RequestBody UserRegistrationRequestDto requestDto);
}

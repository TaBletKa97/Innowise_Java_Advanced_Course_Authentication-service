package com.innowise.authentication.controller;

import com.innowise.authentication.repository.entity.Role;
import com.innowise.authentication.service.AuthService;
import com.innowise.authentication.service.dto.LoginRequestDto;
import com.innowise.authentication.service.dto.RegistrationRequestDto;
import com.innowise.authentication.service.dto.RegistrationResponseDto;
import com.innowise.authentication.utils.JwtTokenUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.boot.liquibase.autoconfigure.LiquibaseAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;

import static com.innowise.authentication.utils.Constants.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(MockitoExtension.class)
@EnableAutoConfiguration(exclude = {
        DataSourceAutoConfiguration.class,
        DataSourceTransactionManagerAutoConfiguration.class,
        HibernateJpaAutoConfiguration.class,
        LiquibaseAutoConfiguration.class
})
class AuthenticationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private JwtTokenUtils tokenUtils;

    @BeforeEach
    void setUp() {
        when(tokenUtils.getLogin(anyString())).thenReturn("login");
        when(tokenUtils.getUserId(anyString())).thenReturn(1L);
        when(tokenUtils.getRole(anyString())).thenReturn("ADMIN");
    }

    @Test
    void validateToken() throws Exception {
        Map<String, String> response = new HashMap<>();
        response.put(ACCESS_TOKEN, "token");
        response.put(REFRESH_TOKEN, "token");
        when(authService.validateToken(any())).thenReturn(response);

        mockMvc.perform(get("/validate").header(HEADER_AUTHORIZATION, "Bearer token"))
                .andExpect(status().isOk())
                .andExpect(content().string(objectMapper.writeValueAsString(response)));
    }

    @Test
    void refreshToken() throws Exception {
        var request = Map.of(ACCESS_TOKEN, "atOld", REFRESH_TOKEN, "rtOld");
        var expectedResponse = Map.of(ACCESS_TOKEN, "at", REFRESH_TOKEN, "rt");

        when(authService.refresh(any())).thenReturn(expectedResponse);
        when(tokenUtils.isValidRefreshToken(anyString())).thenReturn(true);

        mockMvc.perform(post("/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.accessToken").value("at"))
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.refreshToken").value("rt"));
    }

    @Test
    void register() throws Exception {
        final String email = "user@gmail.com";
        var request = new RegistrationRequestDto(email, "password", "name", "surname", LocalDate.of(1970, 1, 1));

        when(authService.register(any())).thenReturn(
                new RegistrationResponseDto(1L, email, Role.USER));

        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void login() throws Exception {
        final String email = "user@gmail.com";
        var request = new LoginRequestDto(email, "password");
        var expectedResponse = Map.of(ACCESS_TOKEN, "at", REFRESH_TOKEN, "rt");

        when(authService.login(any())).thenReturn(expectedResponse);

        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.accessToken").value("at"))
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.refreshToken").value("rt"));
    }
}
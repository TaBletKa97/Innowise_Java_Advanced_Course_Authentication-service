package com.innowise.authentication;

import com.innowise.authentication.utils.JwtTokenUtils;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static com.innowise.authentication.utils.Constants.BEARER;
import static com.innowise.authentication.utils.Constants.HEADER_AUTHORIZATION;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtSecurityFilterTest {

    @Mock
    private JwtTokenUtils tokenUtils;

    @Mock
    private FilterChain filterChain;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @InjectMocks
    private JwtSecurityFilter  securityFilter;

    @BeforeEach
    void setUp() {
        securityFilter =  new JwtSecurityFilter(tokenUtils);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    void testDoFilterInternalWithValidToken() throws Exception {
        final String validToken = "validToken";
        request.addHeader(HEADER_AUTHORIZATION, BEARER + validToken);

        when(tokenUtils.getLogin(anyString())).thenReturn("user");
        when(tokenUtils.getUserId(anyString())).thenReturn(1L);
        when(tokenUtils.getRole(anyString())).thenReturn("USER");

        securityFilter.doFilter(request, response, filterChain);

        verify(tokenUtils, times(1)).getLogin(validToken);
        verify(tokenUtils, times(1)).getUserId(validToken);
        verify(tokenUtils, times(1)).getRole(validToken);
    }

    @Test
    void testDoFilterInternalWithoutAuthorizationHeader() throws Exception {
        securityFilter.doFilter(request, response, filterChain);

        verify(tokenUtils, never()).getLogin(anyString());
        verify(tokenUtils, never()).getUserId(anyString());
        verify(tokenUtils, never()).getRole(anyString());
    }

    @Test
    void testDoFilterInternalWithInvalidToken() throws Exception {
        String invalidToken = "invalidToken";
        request.addHeader(HEADER_AUTHORIZATION, BEARER + invalidToken);

        when(tokenUtils.getLogin(anyString())).thenThrow(JwtException.class);

        securityFilter.doFilter(request, response, filterChain);

        verify(tokenUtils, times(1)).getLogin(invalidToken);
        verify(tokenUtils, never()).getUserId(anyString());
        verify(tokenUtils, never()).getRole(anyString());
    }
}
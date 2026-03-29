package com.innowise.authentication.configurations;

import com.innowise.authentication.external.UserHttpClient;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.service.registry.ImportHttpServices;

@Configuration
@ImportHttpServices(basePackages = "com.innowise.authentication.external", types = UserHttpClient.class)
public class HttpUserConfiguration {
}

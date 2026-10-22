package io.mosip.certify.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web MVC Configuration
 * Registers custom converters for handling form-urlencoded data
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    private final AuthorizationDetailsConverter authorizationDetailsConverter;

    public WebMvcConfig(AuthorizationDetailsConverter authorizationDetailsConverter) {
        this.authorizationDetailsConverter = authorizationDetailsConverter;
    }

    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addConverter(authorizationDetailsConverter);
    }
}


package io.mosip.certify.core.config;

import java.io.IOException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

@Component
public class LocalAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Autowired
    private HandlerExceptionResolver handlerExceptionResolver;

    public LocalAuthenticationEntryPoint() {
    }

    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        this.handlerExceptionResolver.resolveException(request, response, (Object)null, authException);
    }
}

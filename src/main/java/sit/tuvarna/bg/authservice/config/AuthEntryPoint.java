package sit.tuvarna.bg.authservice.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import sit.tuvarna.bg.authservice.enums.AuthErrorCode;
import sit.tuvarna.bg.authservice.web.dto.responses.SimpleErrorResponse;

import java.io.IOException;

@Component
public class AuthEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
            SimpleErrorResponse error = new SimpleErrorResponse(
                AuthErrorCode.BAD_API_KEY.name(),
                "Missing or invalid X-Internal-Api-Key header"
        );

        new ObjectMapper().writeValue(response.getWriter(), error);
    }
}

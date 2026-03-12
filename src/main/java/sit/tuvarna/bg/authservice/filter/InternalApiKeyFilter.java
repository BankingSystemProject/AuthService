package sit.tuvarna.bg.authservice.filter;


import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import sit.tuvarna.bg.authservice.config.InternalApiKeyProperties;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class InternalApiKeyFilter extends OncePerRequestFilter {
    private static final String API_KEY_HEADER = "X-Internal-Api-Key";

    private final InternalApiKeyProperties props;
    private final ObjectMapper objectMapper;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String servletPath = request.getServletPath();
        if(!isProtectedPath(servletPath)) {
            filterChain.doFilter(request, response);
            return;
        }

        String key = request.getHeader(API_KEY_HEADER);
        if(key == null || !key.equals(props.getApiKey())){
            log.warn("Rejected internal request to {} — invalid or missing API key", servletPath);
            sendUnauthorized(response, request);
            return;
        }
        filterChain.doFilter(request,response);
    }

    private void sendUnauthorized(HttpServletResponse response, HttpServletRequest request) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), Map.of(
                "status", 401,
                "error", "Unauthorized",
                "message", "Missing or invalid " + API_KEY_HEADER + " header",
                "timestamp", LocalDateTime.now().toString(),
                "path", request.getRequestURI()
        ));
    }

    private boolean isProtectedPath(String path) {
        return path.equals("/api/v1/tokens/issue")
                || path.equals("/api/v1/tokens/revoke-all");
    }
}

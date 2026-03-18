package sit.tuvarna.bg.authservice.filter;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;
import sit.tuvarna.bg.authservice.config.InternalApiKeyProperties;
import sit.tuvarna.bg.authservice.model.dto.AuthError;
import sit.tuvarna.bg.authservice.model.dto.AuthErrorCode;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class InternalApiKeyFilter extends OncePerRequestFilter {
    private static final String API_KEY_HEADER = "X-Internal-Api-Key";

    private final InternalApiKeyProperties props;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {


        String key = request.getHeader(API_KEY_HEADER);
        log.warn("Header key='{}', props key='{}'", key, props.getApiKey());
        if (key == null || !key.equals(props.getApiKey())) {
            log.warn("Rejected internal request to {} — invalid or missing API key",  request.getServletPath());
            throw new AuthError(AuthErrorCode.BAD_API_KEY,
                    "Missing or invalid X-Internal-Api-Key header");
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getServletPath().startsWith("/api/v1/auth/issue");
    }
}

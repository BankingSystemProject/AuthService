package sit.tuvarna.bg.authservice.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import sit.tuvarna.bg.authservice.blacklistedToken.service.BlacklistedTokenService;
import sit.tuvarna.bg.authservice.model.dto.AuthError;
import sit.tuvarna.bg.authservice.model.dto.AuthErrorCode;
import sit.tuvarna.bg.authservice.service.JwtService;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final BlacklistedTokenService blacklistService;

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String token = extractToken(request);

        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                if (jwtService.isStructurallyValid(token)
                        && !blacklistService.isBlacklisted(token)) {

                    Claims claims = jwtService.parseAllClaims(token);

                    @SuppressWarnings("unchecked")
                    List<String> roles = (List<String>) claims.get("roles");
                    if (roles == null) {
                        roles = Collections.emptyList();
                    }

                    List<SimpleGrantedAuthority> authorities = roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());

                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(
                                    claims.getSubject(), null, authorities);
                    auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } catch (JwtException | IllegalArgumentException e) {
                log.debug("JWT filter rejected token: {}", e.getMessage());
                throw new AuthError(AuthErrorCode.MALFORMED_TOKEN, e.getMessage());
            }
        }

        chain.doFilter(request, response);
    }


    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(header) && header.startsWith(BEARER_PREFIX)) {
            return header.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Skip filter for public auth endpoints or internal-only endpoints to reduce overhead
        String path = request.getServletPath();
        return path.startsWith("/api/v1/auth/refresh")
                || path.startsWith("/api/v1/auth/validate")
                || path.startsWith("/api/v1/auth/issue");
    }
}

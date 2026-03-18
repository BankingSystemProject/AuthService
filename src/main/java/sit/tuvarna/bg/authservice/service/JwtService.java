package sit.tuvarna.bg.authservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import sit.tuvarna.bg.authservice.config.JwtProperties;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties props;

    private SecretKey signingKey(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(props.getSecret()));
    }

    public String generateAccessToken(String userId, String username, Set<String> roles){
        Instant now = Instant.now();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(username)
                .issuer(props.getIssuer())
                .claim("userId",userId)
                .claim("roles", roles)
                .claim("type", "access")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(props.getAccessTokenExpiration())))
                .signWith(signingKey(),Jwts.SIG.HS256)
                .compact();
    }
    public String generateRefreshToken(String userId, String username){
        Instant now = Instant.now();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(username)
                .issuer(props.getIssuer())
                .claim("userId", userId)
                .claim("type", "refresh")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(props.getRefreshTokenExpiration())))
                .signWith(signingKey(),Jwts.SIG.HS256)
                .compact();
    }

    public Claims parseAllClaims(String token){
        return Jwts.parser()
                .verifyWith(signingKey())
                .requireIssuer(props.getIssuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }


    public Claims parseExpiredClaims(String token){
        try{
            return parseAllClaims(token);
        }catch (ExpiredJwtException e){
            return e.getClaims();
        }
    }

    public boolean isStructurallyValid(String token){
        try {
            parseAllClaims(token);
            return true;
        }catch (JwtException | IllegalArgumentException e) {
            log.debug("Token structurally invalid: {}", e.getMessage());
            return false;
        }
    }

    public String extractJti(String token){
        return parseAllClaims(token).getId();
    }

    public String extractUsername(String token){
        return parseAllClaims(token).getSubject();
    }


    public String extractUserId(String token){
        return parseAllClaims(token).get("userId").toString();
    }
    public String extractType(String token){
        return parseAllClaims(token).get("type").toString();
    }
    public Instant extractExpiration(String token) {
        return parseAllClaims(token).getExpiration().toInstant();
    }

    public Instant extractIssuedAt(String token) {
        return parseAllClaims(token).getIssuedAt().toInstant();
    }

    public Set<String> extractRoles(Claims claims) {
        Object raw = claims.get("roles");
        if(raw instanceof List<?> list){
            return list.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .collect(Collectors.toSet());
        }
        return Set.of();
    }

    public long accessExpiresInSeconds(){
        return props.getAccessTokenExpiration()/1000;
    }
    public long refreshExpiresInSeconds(){
        return props.getRefreshTokenExpiration()/1000;
    }


}
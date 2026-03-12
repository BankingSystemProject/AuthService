package sit.tuvarna.bg.authservice.blacklistedToken.service;

import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sit.tuvarna.bg.authservice.blacklistedToken.model.BlacklistedToken;
import sit.tuvarna.bg.authservice.blacklistedToken.repository.BlacklistedTokenRepository;
import sit.tuvarna.bg.authservice.service.JwtService;

import java.time.Instant;

@Service
@Slf4j
public class BlacklistedTokenService {
    private final BlacklistedTokenRepository blacklistedTokenRepository;
    private final JwtService jwtService;

    @Autowired
    public BlacklistedTokenService(BlacklistedTokenRepository blacklistedTokenRepository, JwtService jwtService) {
        this.blacklistedTokenRepository = blacklistedTokenRepository;
        this.jwtService = jwtService;
    }
    @Transactional
//    @CachePut(value = "blacklist", key = "#result.jti")
    public void blacklist(String rawToken, String reason) {
        Claims claims = resolveClaims(rawToken);

        String jti = claims.getId();
        if (blacklistedTokenRepository.existsByJti(jti)) {
            log.debug("Token {} already blacklisted", jti);
            return;
        }

        BlacklistedToken entry = BlacklistedToken.builder()
                .jti(jti)
                .expiresAt(jwtService.extractExpiration(rawToken) != null
                        ? jwtService.extractExpiration(rawToken)
                        : Instant.now())
                .reason(reason)
                .build();

         blacklistedTokenRepository.save(entry);
        log.info("Blacklisted token jti={}  reason={}", jti, reason);
    }

    public boolean existsByJti(String jti) {
        return blacklistedTokenRepository.existsByJti(jti);
    }
    public void save(BlacklistedToken blacklistedToken) {
        blacklistedTokenRepository.save(blacklistedToken);
    }

    public boolean isBlacklisted(String rawToken) {
        try {
            // Use parseExpiredClaims so we can still check blacklist on expired tokens
            Claims claims;
            try {
                claims = jwtService.parseAllClaims(rawToken);
            } catch (Exception e) {
                claims = jwtService.parseExpiredClaims(rawToken);
            }
            return isJtiBlacklisted(claims.getId()); //check later
        } catch (Exception e) {
            // Malformed token — treat as blacklisted
            return true;
        }
    }
    @Cacheable(value = "blacklist", key = "#jti")
    public boolean isJtiBlacklisted(String jti) {
        return blacklistedTokenRepository.existsByJti(jti);
    }

    private Claims resolveClaims(String rawToken){
        try{
            return jwtService.parseAllClaims(rawToken);
        }catch (Exception e){
            Claims claims = jwtService.parseExpiredClaims(rawToken);
            if(claims==null){
                throw new IllegalArgumentException("Cannot blacklist: token is malformed or has invalid signature");
            }
            return claims;
        }
    }
}

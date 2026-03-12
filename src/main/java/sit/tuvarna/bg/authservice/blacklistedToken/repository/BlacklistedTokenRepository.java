package sit.tuvarna.bg.authservice.blacklistedToken.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import sit.tuvarna.bg.authservice.blacklistedToken.model.BlacklistedToken;

import java.time.Instant;

@Repository
public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, String> {

    boolean existsByJti(String jti);
    @Modifying
    @Transactional
    @Query("DELETE FROM BlacklistedToken b WHERE b.expiresAt < :now")
    int deleteByExpiresAtBefore(Instant now);
}

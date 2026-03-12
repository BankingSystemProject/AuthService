package sit.tuvarna.bg.authservice.blacklistedToken.scheduler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import sit.tuvarna.bg.authservice.blacklistedToken.repository.BlacklistedTokenRepository;

import java.time.Instant;

@Component
@Slf4j
public class BlacklistCleanupTask {

    private final BlacklistedTokenRepository blacklistedTokenRepository;

    @Autowired
    public BlacklistCleanupTask(BlacklistedTokenRepository blacklistedTokenRepository) {
        this.blacklistedTokenRepository = blacklistedTokenRepository;
    }

    @Scheduled(cron = "0 0 * * * *")
    public void removeBlacklistedTokens(){
        int count = blacklistedTokenRepository.deleteByExpiresAtBefore(Instant.now());
        if(count>0){
            log.info("Cleaned up {} expired blacklist entries", count);
        }
    }
}

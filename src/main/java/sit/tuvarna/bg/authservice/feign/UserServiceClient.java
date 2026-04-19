package sit.tuvarna.bg.authservice.feign;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@FeignClient(
        name = "user-service",
        url = "${services.user.url}"
)
public interface UserServiceClient {

    @PostMapping("/api/v1/internal/{userId}/2fa-secret")
    void storeTwoFactorSecret(
            @PathVariable UUID userId,
            @RequestBody String secret
    );

    @GetMapping("/api/v1/internal/{userId}/2fa-secret")
    String getTwoFactorSecret(@PathVariable UUID userId);

    @PostMapping("/api/v1/internal/{userId}/2fa/enable")
    void enableTwoFactor(@PathVariable UUID userId);
}

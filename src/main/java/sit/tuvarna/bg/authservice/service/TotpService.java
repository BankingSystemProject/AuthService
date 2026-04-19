package sit.tuvarna.bg.authservice.service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TotpService {

    private final GoogleAuthenticator gAuth;
    private final String issuer;

    @Autowired
    public TotpService(@Value("${security.totp.issuer}") String issuer) {
        this.issuer = issuer;
        GoogleAuthenticatorConfig config = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder()
                .setTimeStepSizeInMillis(30000) // 30 seconds
                .setWindowSize(1) // allow 1 time step before and after
                .setCodeDigits(6) // 6-digit codes
                .build();
        this.gAuth= new GoogleAuthenticator(config);
    }

    public String generateSecret(){
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        return key.getKey();
    }

    public boolean verifyCode(String secret, int code) {
        return gAuth.authorize(secret, code);
    }
    public String buildOtpAuthUrl(String accountName, String secret) {
        // otpauth://totp/Issuer:accountName?secret=SECRET&issuer=Issuer
        return String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s",
                issuer,
                accountName,
                secret,
                issuer
        );
    }


}

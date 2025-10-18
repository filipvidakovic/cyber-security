package org.cybersecurity.services.user;

import lombok.RequiredArgsConstructor;
import org.cybersecurity.model.user.BaseUser;
import org.cybersecurity.model.user.EmailVerificationToken;
import org.cybersecurity.repositories.user.EmailVerificationTokenRepository;
import org.cybersecurity.repositories.user.UserRepository;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokenRepository;
    private final JavaMailSender mailSender;
    private final UserRepository userRepository;

    private static final long EXPIRATION_MINUTES = 15; // 15 minutes

    @Transactional
    public void sendVerificationEmail(BaseUser user) {
        // Create token
        EmailVerificationToken token = EmailVerificationToken.create(user, EXPIRATION_MINUTES);
        tokenRepository.save(token);

        // Construct verification URL
        String verificationUrl = "https://localhost:8443/api/auth/confirm?token=" + token.getToken();

        // Send email
        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(user.getEmail());
        mailMessage.setSubject("Confirm your email address");
        mailMessage.setText("""
                Welcome to CyberSecurity App!
                
                Please confirm your email by clicking the link below (valid for 15 minutes):
                %s
                """.formatted(verificationUrl));

        mailSender.send(mailMessage);
    }

    @Transactional
    public boolean confirmEmail(String token) {
        var optionalToken = tokenRepository.findByToken(token);
        if (optionalToken.isEmpty()) return false;

        var verificationToken = optionalToken.get();
        if (verificationToken.isExpired()) {
            tokenRepository.delete(verificationToken);
            return false;
        }

        BaseUser user = verificationToken.getUser();
        user.setEnabled(true);
        userRepository.save(user);
        tokenRepository.delete(verificationToken);
        return true;
    }
}

package org.cybersecurity.controllers.auth;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.cybersecurity.config.jwt.JwtTokenUtil;
import org.cybersecurity.dto.auth.*;
import org.cybersecurity.model.user.BaseUser;
import org.cybersecurity.services.user.EmailVerificationService;
import org.cybersecurity.services.user.UserService;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
@RequestMapping("/api/auth")
@Validated
public class AuthController {

    private final UserService userService;
    private final EmailVerificationService emailVerificationService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenUtil jwtTokenUtil;

    private static final long TIME_15_MINUTES = 15 * 60 * 1000;
    private static final long TIME_7_DAYS = 7 * 24 * 60 * 60 * 1000;

    @PostMapping("/signup")
    public ResponseEntity<String> registerUser(@Valid @RequestBody RegisterUserDto dto) {
        if (userService.registerUser(dto)) {
            return ResponseEntity.ok("User registered. Please check your email to confirm your account.");
        }
        return ResponseEntity.badRequest().body("User registration failed.");
    }

    @GetMapping("/confirm")
    public ResponseEntity<String> confirmEmail(@RequestParam("token") String token) {
        boolean confirmed = emailVerificationService.confirmEmail(token);
        return confirmed
                ? ResponseEntity.ok("Email confirmed successfully! You can now log in.")
                : ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid or expired token.");
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginDto request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        BaseUser authenticatedUser = userService.getUserByEmail(request.getEmail());

        if (!authenticatedUser.isEnabled()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(null);
        }

        String accessToken = jwtTokenUtil.generateToken(authenticatedUser.getEmail(), TIME_15_MINUTES);
        String refreshToken = jwtTokenUtil.generateToken(authenticatedUser.getEmail(), TIME_7_DAYS);

        return ResponseEntity.ok(new LoginResponseDto(
                authenticatedUser.getId(),
                authenticatedUser.getEmail(),
                accessToken,
                refreshToken,
                authenticatedUser.getUserRole()
        ));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponseDto> refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        if (jwtTokenUtil.validateToken(refreshToken)) {
            String username = jwtTokenUtil.extractUsername(refreshToken);
            BaseUser user = userService.getUserByEmail(username);

            String newAccessToken = jwtTokenUtil.generateToken(username, TIME_15_MINUTES);
            String newRefreshToken = jwtTokenUtil.generateToken(username, TIME_7_DAYS);

            return ResponseEntity.ok(new LoginResponseDto(
                    user.getId(),
                    user.getEmail(),
                    newAccessToken,
                    newRefreshToken,
                    user.getUserRole()
            ));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}

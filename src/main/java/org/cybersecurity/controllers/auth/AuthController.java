package org.cybersecurity.controllers.auth;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.cybersecurity.config.jwt.JwtTokenUtil;
import org.cybersecurity.dto.auth.LoginDto;
import org.cybersecurity.dto.auth.LoginResponseDto;
import org.cybersecurity.dto.auth.RegisterUserDto;
import org.cybersecurity.model.user.BaseUser;
import org.cybersecurity.services.user.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@CrossOrigin(origins="*")
@RequestMapping("/api/auth")
@Validated
public class AuthController {

    private final UserService userService;

    private final AuthenticationManager authenticationManager;

    private final JwtTokenUtil jwtTokenUtil;
    private static final long TIME_15_MINUTES = 15 * 60 * 1000;
    private static final long TIME_7_DAYS = 7 * 24 * 60 * 60 * 1000;

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginDto request) {
        // Authenticate user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        BaseUser authenticatedUser = userService.getUserByEmail(request.getEmail());

        String accessToken = jwtTokenUtil.generateToken(authenticatedUser.getEmail(), TIME_15_MINUTES);
        String refreshToken = jwtTokenUtil.generateToken(authenticatedUser.getEmail(), TIME_7_DAYS);

        return ResponseEntity.ok(new LoginResponseDto(authenticatedUser.getId(),
                authenticatedUser.getEmail(),
                accessToken,
                refreshToken,
                authenticatedUser.getUserRole()));
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

    @PostMapping("/signup")
    public ResponseEntity<Boolean> registerUser (@Valid @RequestBody RegisterUserDto registerUserDto) {
        return userService.registerUser(registerUserDto)
                ? ResponseEntity.ok(true)
                : ResponseEntity.badRequest().build();
    }
}

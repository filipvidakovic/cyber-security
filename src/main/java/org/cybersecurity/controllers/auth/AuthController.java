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

@RestController
@RequiredArgsConstructor
@CrossOrigin(origins="*")
@RequestMapping("/api/auth")
@Validated
public class AuthController {

    private final UserService userService;

    private final AuthenticationManager authenticationManager;

    private final JwtTokenUtil jwtTokenUtil;

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginDto request) {
        // Authenticate user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        BaseUser authenticatedUser = userService.getUserByEmail(request.getEmail());

        String token = jwtTokenUtil.generateToken(authenticatedUser.getEmail());

        return ResponseEntity.ok(new LoginResponseDto(authenticatedUser.getId(),
                authenticatedUser.getEmail(),
                token,
                authenticatedUser.getUserRole(),
                null));
    }

    @PostMapping("/signup")
    public ResponseEntity<Boolean> registerUser (@Valid @RequestBody RegisterUserDto registerUserDto) {
        return userService.registerUser(registerUserDto)
                ? ResponseEntity.ok(true)
                : ResponseEntity.badRequest().build();
    }
}

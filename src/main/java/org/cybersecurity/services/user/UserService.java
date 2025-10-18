package org.cybersecurity.services.user;

import lombok.RequiredArgsConstructor;
import org.cybersecurity.dto.auth.RegisterUserDto;
import org.cybersecurity.mapper.auth.UserMapper;
import org.cybersecurity.model.user.BaseUser;
import org.cybersecurity.model.user.UserRole;
import org.cybersecurity.repositories.user.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<BaseUser> ret = userRepository.findByEmail(email);
        if (ret.isPresent()) {
            return org.springframework.security.core.userdetails.User
                    .withUsername(email)
                    .password(ret.get().getPassword() != null ? ret.get().getPassword() : "DUMMY_PASSWORD")
                    .roles(ret.get().getUserRole().toString())
                    .build();
        }
        throw new UsernameNotFoundException("User not found with this email: " + email);
    }

    public boolean registerUser(RegisterUserDto registerUserDto) {
        registerUserDto.setPassword(passwordEncoder.encode(registerUserDto.getPassword()));
        userRepository.save(UserMapper.toEntity(registerUserDto));
        return true;
    }

    public BaseUser getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with this email: " + email));
    }

    public void enableUser(long userId) {
        BaseUser user = userRepository.findById(userId).orElse(null);
        if (user == null) return;
        user.setEnabled(true);
    }
}

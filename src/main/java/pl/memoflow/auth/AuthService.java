package pl.memoflow.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.memoflow.common.ConflictException;

import java.time.Clock;
import java.time.Instant;
import java.util.Locale;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;
    private final JwtService jwtService;

    private static final String INVALID_CREDENTIALS = "Nieprawidłowy e-mail lub hasło";

    @Transactional
    public UserResponse register(RegisterRequest request) {
        String email = normalizeEmail(request.email());

        if (userRepository.existsByEmail(email)) {
            throw new ConflictException("Ten e-mail jest już zajęty");
        }

        User user = new User(
                email,
                passwordEncoder.encode(request.password()),
                Instant.now(clock));
        User saved = userRepository.save(user);

        return new UserResponse(saved.getId(), saved.getEmail());
    }

    @Transactional(readOnly = true)
    public TokenResponse login(LoginRequest request) {
        String email = normalizeEmail(request.email());

        User user = userRepository.findByEmail(email)
                .filter(found -> passwordEncoder.matches(request.password(), found.getPasswordHash()))
                .orElseThrow(() -> new BadCredentialsException(INVALID_CREDENTIALS));
        return new TokenResponse(jwtService.generateToken(user));
    }

    static String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}

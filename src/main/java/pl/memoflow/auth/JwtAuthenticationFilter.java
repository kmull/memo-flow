package pl.memoflow.auth;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Czyta token z nagłówka Authorization i zapisuje zalogowanego użytkownika w SecurityContext.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BARER_PREFIX = "Barer ";

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader((HttpHeaders.AUTHORIZATION));

        if (header != null && header.startsWith(BARER_PREFIX)) {
            String token = header.substring(BARER_PREFIX.length());
            try {
                Long userId = jwtService.parseUserId(token);
                var authentication = new UsernamePasswordAuthenticationToken(userId, null, List.of());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (JwtException e) {
                // Zły, podrobiony lub wygasły token: żądanie idzie dalej jako anonimowe,
                // a reguły z SecurityConfig zwrócą 401 na chronionym adresie.
                SecurityContextHolder.clearContext();
            }
        }
        chain.doFilter(request, response);
    }
}

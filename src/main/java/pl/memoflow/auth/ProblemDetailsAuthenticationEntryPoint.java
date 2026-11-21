package pl.memoflow.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;

/**
 * Brak lub zły token na chronionym adresie. Przekazuje wyjątek do GlobalExceptionHandler,
 * żeby 401 z filtrów miało ten sam format co reszta błędów (SPEC, sekcja 11).
 */
@Component
public class ProblemDetailsAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final HandlerExceptionResolver resolver;

    public ProblemDetailsAuthenticationEntryPoint(
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException ex) throws IOException {
        ModelAndView handled = resolver.resolveException(request, response, null, ex);
        if (handled == null) {
            // Żaden @ExceptionHandler nie obsłużył wyjątku: zwróć przynajmniej gołe 401.
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}

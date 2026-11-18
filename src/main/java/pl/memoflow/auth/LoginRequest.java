package pl.memoflow.auth;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank(message = "E-mail jest wymagany") String email,
        @NotBlank(message = "Hasło jest wymagane") String password
) {
}

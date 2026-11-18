package pl.memoflow.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "E-mail jest wymagany")
        @Email(message = "Niepoprawny format e-maila")
        @Size(max = 254, message = "E-mail może mieć najwyżej 254 znaki") String email,

        @NotBlank(message = "Hasło jest wymagane")
        @Size(min = 8, max = 64, message = "Hasło musi mieć od {min} do {max} znaków")
        @Pattern(
                regexp = "^(?=.*\\d)(?=.*\\p{Lu}).*$",
                message = "Hasło musi zawierać co najmniej jedną cyfrę i jedną wielką literę"
        ) String password
) {
}

package com.codingshadows.auth.exception;

import jakarta.servlet.ServletException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.io.Serial;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class JWTException extends ServletException {
    @Serial
    private static final long serialVersionUID = 2L;
    public JWTException(String username, String message) {
        super(String.format("Login failed for [%s]: %s", username, message));
    }
}

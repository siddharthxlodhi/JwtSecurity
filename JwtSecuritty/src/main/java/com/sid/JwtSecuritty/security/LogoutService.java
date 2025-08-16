package com.sid.JwtSecuritty.security;

import com.sid.JwtSecuritty.JwtConfig.Token;
import com.sid.JwtSecuritty.JwtConfig.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;


    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        String header = request.getHeader("AUTHORIZATION");
        if (header == null || !header.startsWith("Bearer ")) {
            return;
        }

       final String jwt = header.substring(7);
        Optional<Token> token = tokenRepository.findByToken(jwt);

        if (token.isPresent()) {
            token.get().setRevoked(true);
            token.get().setExpired(true);
            tokenRepository.save(token.get());
        }

    }
}

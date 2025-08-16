package com.sid.JwtSecuritty.JwtConfig;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Component
@RequiredArgsConstructor
//This JwtAuthenticationFilter will intercept the request and validate token in the header ,if validated store the user in SecurityContextHolder
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal
            (@NonNull HttpServletRequest request,
             @NonNull HttpServletResponse response,
             @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        //Extracting AUTHORIZATION header from request
        final String authHeader = request.getHeader(AUTHORIZATION);

        //If AUTHORIZATION header is null or It not start with Bearer , move to next filter
        //Because if the request is not protected (no need to validate) or if the request is without token (denied)
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt;
        final String userEmail;
        final UserDetails userDetails;
        jwt = authHeader.substring(7);         //Extracting token from header ( Bearer ***********)
        userEmail = jwtService.extractUsername(jwt);      //Extracting the username or userID(unique) from token to verify user in DB

        //If user is not null(means present in DB) and Security context is empty
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            userDetails = userDetailsService.loadUserByUsername(userEmail);    //load the request making user from DB using UserDetailService

            //Checking if the token is revoked(blacklisted) already
            boolean isTokenValid = tokenRepository.findByToken(jwt).map(token -> (!token.isExpired() && !token.isRevoked())).orElse(false);

            //Checking revoked && Validating token(expiry,signature,blacklist) with user in DB
            if (isTokenValid && jwtService.validateToken(jwt, userDetails)) {

                //If token and user is valid , update the SecurityContextHolder
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        //move to next filters, next filter will know that the Security Context is updated
        filterChain.doFilter(request, response);
    }
}

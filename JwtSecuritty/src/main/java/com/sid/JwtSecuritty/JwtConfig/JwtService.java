package com.sid.JwtSecuritty.JwtConfig;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.*;
import java.util.function.Function;

import static io.jsonwebtoken.Jwts.*;

@Service
public class JwtService {
    @Value("${application.security.jwt.secret-key}")
    private String SECRET_KEY;
    @Value("${application.security.jwt.access_expiration}")
    private long accessTokenExpiration;
    @Value("${application.security.jwt.refresh_expiration}")
    private long refreshTokenExpiration;


    //Generate JWT access token using user information and expiration
    public String generateAccessToken(HashMap<String, Object> claims, UserDetails userDetails) {
        return buildToken(claims, userDetails, accessTokenExpiration);
    }

    //Generate JWT access token using user information and expiration
    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshTokenExpiration);
    }

    //Utility method used by above method
    private String buildToken(HashMap<String, Object> claims, UserDetails userDetails, long expiration) {
        List<String> authorities = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
        return builder()
                .subject(userDetails.getUsername())
                .claims(claims)
                .claim("typ", "jwt")
                .claim("authorities", authorities)  //Passing user authorities
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();

    }

    //Creating signing key with SECRET_KEY
    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    //--------------------------------------------------------------------------------------------------------------------------------------------------------------

    //if userId in token and db are same and token is not expired
    public boolean validateToken(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    //take token and return required claim
    public <T> T extractClaims(String token, Function<Claims, T> claimResolver) {
        Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);

    }

    //Extract username
    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    //Check if the token is expired or not
    private boolean isTokenExpired(String token) {
        return extractClaims(token, Claims::getExpiration).before(new Date());
    }

    //verify token signature , and return all claims
    private Claims extractAllClaims(String token) {
        return parser()
                .verifyWith((SecretKey) getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

    }


}

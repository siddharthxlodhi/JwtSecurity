package com.sid.JwtSecuritty.auth;

import com.sid.JwtSecuritty.JwtConfig.JwtService;
import com.sid.JwtSecuritty.email.EmailService;
import com.sid.JwtSecuritty.role.RoleRepository;
import com.sid.JwtSecuritty.user.Token;
import com.sid.JwtSecuritty.user.TokenRepository;
import com.sid.JwtSecuritty.user.User;
import com.sid.JwtSecuritty.user.UserRepository;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Set;

import static com.sid.JwtSecuritty.email.EmailTemplateName.ACTIVATE_ACCOUNT;

@RequiredArgsConstructor
@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final EmailService emailService;
    private final AuthenticationManager authenticationManager;

    @Value("${application.mailing.activation-url}")
    private String activationUrl;

    public void register(RegistrationRequest request) throws MessagingException {
        var userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new IllegalArgumentException("Role USER was not initialized"));
        var user = User.builder().firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .dateOfBirth(request.getDateOfBirth())
                .createdDate(LocalDateTime.now())
                .roles(Set.of(userRole))
                .enabled(false)
                .accountLocked(false)
                .build();
        userRepository.save(user);
        sendValidationEmail(user);
    }

//    @Transactional
    public ResponseEntity<String> activateAccount(String activationToken) throws MessagingException {
        Token token = tokenRepository.findByActivationToken(activationToken).orElseThrow(() -> new RuntimeException("Invalid Token"));
        if (LocalDateTime.now().isAfter(token.getExpiresAt())) {
            sendValidationEmail(token.getUser());
            throw new RuntimeException("Token has expired,a new token has been sent");
        }
        User user = userRepository.findById(token.getUser().getId())
                .orElseThrow(() -> new UsernameNotFoundException("User not found under this token"));
        user.setEnabled(true);
        userRepository.save(user);
        token.setValidatedAt(LocalDateTime.now());
        tokenRepository.save(token);
        return new ResponseEntity<>("Activated", HttpStatus.ACCEPTED);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        var authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                authenticationRequest.getEmail(), authenticationRequest.getPassword()
        ));

        HashMap<String, Object> claims = new HashMap<>();
        var user = (User) authentication.getPrincipal();
        claims.put("fullName", user.getFullName());
        String jwt = jwtService.generateToken(claims, user);
        return AuthenticationResponse.builder().jwtToken(jwt).build();

    }


    private void sendValidationEmail(User user) throws MessagingException {
        String activationCode = generateAndSaveActivationToken(user);

        emailService.sendEmail(
                user.getEmail(),
                user.getFullName(),
                ACTIVATE_ACCOUNT,
                activationUrl,
                "Account Activation",
                activationCode
        );


    }

    private String generateAndSaveActivationToken(User user) {
        // Generate a token
        String generatedToken = generateActivationCode();
        var token = Token.builder()
                .activationToken(generatedToken)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .user(user)
                .build();
        tokenRepository.save(token);

        return generatedToken;
    }

    private String generateActivationCode() {
        String characters = "0123456789";
        StringBuilder codeBuilder = new StringBuilder();

        SecureRandom secureRandom = new SecureRandom();

        for (int i = 0; i < 6; i++) {
            int randomIndex = secureRandom.nextInt(characters.length());
            codeBuilder.append(characters.charAt(randomIndex));
        }

        return codeBuilder.toString();
    }

}

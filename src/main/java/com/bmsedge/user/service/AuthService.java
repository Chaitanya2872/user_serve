package com.bmsedge.user.service;

import com.bmsedge.user.dto.AuthResponse;
import com.bmsedge.user.dto.LoginRequest;
import com.bmsedge.user.dto.SignUpRequest;
import com.bmsedge.user.model.Role;
import com.bmsedge.user.model.User;
import com.bmsedge.user.repository.UserRepository;
import com.bmsedge.user.security.JwtUtils;
import com.bmsedge.user.security.UserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
@Transactional
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    public AuthResponse registerUser(SignUpRequest signUpRequest) {
        logger.info("Starting user registration for email: {}", signUpRequest.getEmail());

        try {
            // Check if user already exists
            if (userRepository.existsByEmail(signUpRequest.getEmail())) {
                logger.error("Email already exists: {}", signUpRequest.getEmail());
                throw new RuntimeException("Email is already taken!");
            }

            // Create new user
            User user = new User();
            user.setFullName(signUpRequest.getFullName());
            user.setEmail(signUpRequest.getEmail());
            user.setPassword(encoder.encode(signUpRequest.getPassword()));
            user.setActive(true);
            user.setCreatedAt(LocalDateTime.now());
            user.setUpdatedAt(LocalDateTime.now());

            // Set default role if not provided
            Set<Role> roles = signUpRequest.getRoles();
            if (roles == null || roles.isEmpty()) {
                roles = new HashSet<>();
                roles.add(Role.USER); // Default role
            }

            // Important: Set roles BEFORE saving to avoid constraint issues
            logger.info("Setting roles for user {}: {}", signUpRequest.getEmail(), roles);
            user.setRoles(roles);

            // Save user to database
            User savedUser = userRepository.save(user);
            logger.info("User registered successfully with ID: {} and roles: {}",
                    savedUser.getId(), savedUser.getRoles());

            // Create UserPrincipal for token generation
            UserPrincipal userPrincipal = UserPrincipal.create(savedUser);

            // Generate tokens
            String accessToken = jwtUtils.generateAccessToken(userPrincipal);
            String refreshToken = jwtUtils.generateRefreshToken(userPrincipal);

            logger.info("Tokens generated successfully for user: {}", savedUser.getEmail());

            // Use userId instead of id to match AuthResponse constructor
            return new AuthResponse(
                    accessToken,
                    refreshToken,
                    savedUser.getId(),  // This will be set as userId
                    savedUser.getFullName(),
                    savedUser.getEmail(),
                    savedUser.getRoles()
            );

        } catch (Exception e) {
            logger.error("Error during user registration: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to register user: " + e.getMessage());
        }
    }

    public AuthResponse authenticateUser(LoginRequest loginRequest) {
        logger.info("Starting authentication for email: {}", loginRequest.getEmail());

        try {
            // First, check if user exists in database
            Optional<User> userOpt = userRepository.findByEmail(loginRequest.getEmail());
            if (!userOpt.isPresent()) {
                logger.error("User not found in database: {}", loginRequest.getEmail());
                throw new RuntimeException("Invalid credentials");
            }

            User user = userOpt.get();
            logger.info("User found in database: {}, active: {}, roles: {}",
                    user.getEmail(), user.isActive(), user.getRoles());

            // Check if user is active
            if (!user.isActive()) {
                logger.error("User account is not active: {}", loginRequest.getEmail());
                throw new RuntimeException("Account is not active");
            }

            // Verify password manually first for debugging
            boolean passwordMatches = encoder.matches(loginRequest.getPassword(), user.getPassword());
            logger.info("Password match result for {}: {}", loginRequest.getEmail(), passwordMatches);

            if (!passwordMatches) {
                logger.error("Password mismatch for user: {}", loginRequest.getEmail());
                throw new RuntimeException("Invalid credentials");
            }

            // Now try Spring Security authentication
            Authentication authentication;
            try {
                authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                loginRequest.getEmail(),
                                loginRequest.getPassword()
                        )
                );
                logger.info("Spring Security authentication successful for: {}", loginRequest.getEmail());
            } catch (BadCredentialsException e) {
                logger.error("Spring Security authentication failed: {}", e.getMessage());
                throw new RuntimeException("Invalid credentials");
            }

            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

            // Update last login time
            user.setLastLogin(LocalDateTime.now());
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);

            // Generate tokens
            String accessToken = jwtUtils.generateAccessToken(userPrincipal);
            String refreshToken = jwtUtils.generateRefreshToken(userPrincipal);

            logger.info("Authentication completed successfully for: {}", loginRequest.getEmail());

            // Use userId instead of id to match AuthResponse constructor
            return new AuthResponse(
                    accessToken,
                    refreshToken,
                    user.getId(),  // This will be set as userId
                    user.getFullName(),
                    user.getEmail(),
                    user.getRoles()
            );

        } catch (Exception e) {
            logger.error("Authentication failed for {}: {}", loginRequest.getEmail(), e.getMessage(), e);
            throw new RuntimeException("Invalid credentials");
        }
    }

    public AuthResponse refreshToken(String refreshToken) {
        logger.info("Processing refresh token request");

        try {
            // Validate refresh token
            if (!jwtUtils.validateJwtToken(refreshToken)) {
                logger.error("Invalid refresh token provided");
                throw new RuntimeException("Invalid refresh token");
            }

            // Extract user info from refresh token
            String email = jwtUtils.getEmailFromJwtToken(refreshToken);

            // Find user in database
            Optional<User> userOpt = userRepository.findByEmail(email);
            if (!userOpt.isPresent()) {
                logger.error("User not found for refresh token: {}", email);
                throw new RuntimeException("User not found");
            }

            User user = userOpt.get();

            // Check if user is still active
            if (!user.isActive()) {
                logger.error("User account is not active during refresh: {}", email);
                throw new RuntimeException("Account is not active");
            }

            // Create UserPrincipal for new token generation
            UserPrincipal userPrincipal = UserPrincipal.create(user);

            // Generate new tokens
            String newAccessToken = jwtUtils.generateAccessToken(userPrincipal);
            String newRefreshToken = jwtUtils.generateRefreshToken(userPrincipal);

            logger.info("Tokens refreshed successfully for user: {}", email);

            // Use userId instead of id to match AuthResponse constructor
            return new AuthResponse(
                    newAccessToken,
                    newRefreshToken,
                    user.getId(),  // This will be set as userId
                    user.getFullName(),
                    user.getEmail(),
                    user.getRoles()
            );

        } catch (Exception e) {
            logger.error("Token refresh failed: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to refresh token: " + e.getMessage());
        }
    }
}
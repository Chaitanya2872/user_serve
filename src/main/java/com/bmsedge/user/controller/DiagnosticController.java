package com.bmsedge.user.controller;

import com.bmsedge.user.model.User;
import com.bmsedge.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/diagnostic")
@CrossOrigin(origins = "*")
public class DiagnosticController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // Check if test users exist
    @GetMapping("/check-users")
    public ResponseEntity<Map<String, Object>> checkUsers() {
        Map<String, Object> result = new HashMap<>();

        // Count total users
        long totalUsers = userRepository.count();
        result.put("totalUsers", totalUsers);

        // List all user emails
        List<String> userEmails = userRepository.findAll().stream()
                .map(User::getEmail)
                .collect(Collectors.toList());
        result.put("userEmails", userEmails);

        // Check specific test users
        Map<String, Boolean> testUsers = new HashMap<>();
        testUsers.put("admin@bmsedge.com", userRepository.existsByEmail("admin@bmsedge.com"));
        testUsers.put("admin2@bmsedge.com", userRepository.existsByEmail("admin2@bmsedge.com"));
        testUsers.put("manager@bmsedge.com", userRepository.existsByEmail("manager@bmsedge.com"));
        testUsers.put("user@bmsedge.com", userRepository.existsByEmail("user@bmsedge.com"));
        result.put("testUsersExist", testUsers);

        return ResponseEntity.ok(result);
    }

    // Test password encoding
    @PostMapping("/test-password")
    public ResponseEntity<Map<String, Object>> testPassword(@RequestBody Map<String, String> request) {
        Map<String, Object> result = new HashMap<>();

        String email = request.get("email");
        String rawPassword = request.get("password");

        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isPresent()) {
            User user = userOpt.get();
            result.put("userFound", true);
            result.put("userEmail", user.getEmail());
            result.put("userActive", user.isActive());
            result.put("userRoles", user.getRoles());

            // Test password match
            boolean passwordMatches = passwordEncoder.matches(rawPassword, user.getPassword());
            result.put("passwordMatches", passwordMatches);

            // Show encoded version of the test password for comparison
            String testEncodedPassword = passwordEncoder.encode(rawPassword);
            result.put("testEncodedPassword", testEncodedPassword);
            result.put("storedPasswordLength", user.getPassword().length());

        } else {
            result.put("userFound", false);
            result.put("message", "User not found with email: " + email);
        }

        return ResponseEntity.ok(result);
    }

    // Get user details
    @GetMapping("/user-details/{email}")
    public ResponseEntity<Map<String, Object>> getUserDetails(@PathVariable String email) {
        Map<String, Object> result = new HashMap<>();

        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isPresent()) {
            User user = userOpt.get();
            result.put("found", true);
            result.put("id", user.getId());
            result.put("email", user.getEmail());
            result.put("fullName", user.getFullName());
            result.put("active", user.isActive());
            result.put("roles", user.getRoles());
            result.put("createdAt", user.getCreatedAt());
            result.put("updatedAt", user.getUpdatedAt());
            result.put("lastLogin", user.getLastLogin());
            // Don't expose the actual password, just its presence
            result.put("hasPassword", user.getPassword() != null && !user.getPassword().isEmpty());
        } else {
            result.put("found", false);
            result.put("message", "User not found");
        }

        return ResponseEntity.ok(result);
    }

    // Reset admin password (emergency use only)
    @PostMapping("/reset-admin-password")
    public ResponseEntity<Map<String, String>> resetAdminPassword() {
        Map<String, String> result = new HashMap<>();

        Optional<User> adminOpt = userRepository.findByEmail("admin@bmsedge.com");

        if (adminOpt.isPresent()) {
            User admin = adminOpt.get();
            admin.setPassword(passwordEncoder.encode("admin123"));
            userRepository.save(admin);
            result.put("status", "success");
            result.put("message", "Admin password reset to: admin123");
        } else {
            result.put("status", "error");
            result.put("message", "Admin user not found");
        }

        return ResponseEntity.ok(result);
    }

    // Check encoder configuration
    @GetMapping("/encoder-info")
    public ResponseEntity<Map<String, Object>> getEncoderInfo() {
        Map<String, Object> result = new HashMap<>();

        // Test encoding
        String testPassword = "test123";
        String encoded1 = passwordEncoder.encode(testPassword);
        String encoded2 = passwordEncoder.encode(testPassword);

        result.put("encoderClass", passwordEncoder.getClass().getName());
        result.put("testPassword", testPassword);
        result.put("encoded1", encoded1);
        result.put("encoded2", encoded2);
        result.put("encodingsMatch", encoded1.equals(encoded2));
        result.put("verifyEncoded1", passwordEncoder.matches(testPassword, encoded1));
        result.put("verifyEncoded2", passwordEncoder.matches(testPassword, encoded2));

        return ResponseEntity.ok(result);
    }
}
package com.bmsedge.user.controller;

import com.bmsedge.user.security.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/validate")
@CrossOrigin(origins = "*")
public class TokenValidationController {

    @Autowired
    private JwtUtils jwtUtils;

    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> validateToken(@RequestParam String token) {
        Map<String, Object> response = new HashMap<>();

        if (jwtUtils.validateJwtToken(token)) {
            String email = jwtUtils.getEmailFromJwtToken(token);
            Long userId = jwtUtils.getUserIdFromJwtToken(token);
            String fullName = jwtUtils.getFullNameFromJwtToken(token);
            List<String> roles = jwtUtils.getRolesFromJwtToken(token);

            response.put("valid", true);
            response.put("email", email);
            response.put("userId", userId);
            response.put("fullName", fullName);
            response.put("roles", roles);
        } else {
            response.put("valid", false);
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        Map<String, String> status = new HashMap<>();
        status.put("status", "UP");
        status.put("service", "Token Validation Service");
        return ResponseEntity.ok(status);
    }
}
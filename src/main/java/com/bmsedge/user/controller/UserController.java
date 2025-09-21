package com.bmsedge.user.controller;

import com.bmsedge.user.dto.MessageResponse;
import com.bmsedge.user.dto.PagedResponse;
import com.bmsedge.user.dto.UserResponse;
import com.bmsedge.user.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = "*", maxAge = 3600)
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserService userService;

    // Get all users with pagination
    @GetMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('CO_ADMIN') or hasRole('MANAGER')")
    public ResponseEntity<PagedResponse<UserResponse>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "ASC") String sortDirection) {

        logger.info("Fetching users - page: {}, size: {}, sortBy: {}, direction: {}",
                page, size, sortBy, sortDirection);

        try {
            Sort.Direction direction = sortDirection.equalsIgnoreCase("DESC")
                    ? Sort.Direction.DESC : Sort.Direction.ASC;
            Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortBy));

            Page<UserResponse> usersPage = userService.getAllUsers(pageable);

            PagedResponse<UserResponse> response = new PagedResponse<>(
                    usersPage.getContent(),
                    usersPage.getNumber(),
                    usersPage.getSize(),
                    usersPage.getTotalElements(),
                    usersPage.getTotalPages(),
                    usersPage.isLast()
            );

            logger.info("Successfully fetched {} users", usersPage.getContent().size());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error fetching users: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // Get all users without pagination (for smaller datasets or dropdowns)
    @GetMapping("/all")
    @PreAuthorize("hasRole('ADMIN') or hasRole('CO_ADMIN') or hasRole('MANAGER')")
    public ResponseEntity<List<UserResponse>> getAllUsersNoPaging() {
        logger.info("Fetching all users without pagination");

        try {
            List<UserResponse> users = userService.getAllUsersNoPaging();
            logger.info("Successfully fetched {} users", users.size());
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            logger.error("Error fetching users: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // Get user by ID
    @GetMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('CO_ADMIN') or hasRole('MANAGER') or #userId == authentication.principal.id")
    public ResponseEntity<?> getUserById(@PathVariable Long userId) {
        logger.info("Fetching user with ID: {}", userId);

        try {
            UserResponse user = userService.getUserById(userId);
            if (user != null) {
                logger.info("Successfully fetched user: {}", user.getEmail());
                return ResponseEntity.ok(user);
            } else {
                logger.warn("User not found with ID: {}", userId);
                Map<String, String> error = new HashMap<>();
                error.put("message", "User not found with ID: " + userId);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
            }
        } catch (Exception e) {
            logger.error("Error fetching user with ID {}: {}", userId, e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", "Error fetching user");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    // Delete user by ID
    @DeleteMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteUser(@PathVariable Long userId) {
        logger.info("Delete request received for user ID: {}", userId);

        try {
            boolean deleted = userService.deleteUser(userId);
            if (deleted) {
                logger.info("Successfully deleted user with ID: {}", userId);
                return ResponseEntity.ok(new MessageResponse("User deleted successfully"));
            } else {
                logger.warn("User not found with ID: {}", userId);
                Map<String, String> error = new HashMap<>();
                error.put("message", "User not found with ID: " + userId);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
            }
        } catch (Exception e) {
            logger.error("Error deleting user with ID {}: {}", userId, e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", "Error deleting user: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    // Soft delete (deactivate) user
    @PutMapping("/{userId}/deactivate")
    @PreAuthorize("hasRole('ADMIN') or hasRole('CO_ADMIN')")
    public ResponseEntity<?> deactivateUser(@PathVariable Long userId) {
        logger.info("Deactivate request received for user ID: {}", userId);

        try {
            UserResponse user = userService.deactivateUser(userId);
            if (user != null) {
                logger.info("Successfully deactivated user with ID: {}", userId);
                return ResponseEntity.ok(user);
            } else {
                logger.warn("User not found with ID: {}", userId);
                Map<String, String> error = new HashMap<>();
                error.put("message", "User not found with ID: " + userId);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
            }
        } catch (Exception e) {
            logger.error("Error deactivating user with ID {}: {}", userId, e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", "Error deactivating user");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    // Reactivate user
    @PutMapping("/{userId}/activate")
    @PreAuthorize("hasRole('ADMIN') or hasRole('CO_ADMIN')")
    public ResponseEntity<?> activateUser(@PathVariable Long userId) {
        logger.info("Activate request received for user ID: {}", userId);

        try {
            UserResponse user = userService.activateUser(userId);
            if (user != null) {
                logger.info("Successfully activated user with ID: {}", userId);
                return ResponseEntity.ok(user);
            } else {
                logger.warn("User not found with ID: {}", userId);
                Map<String, String> error = new HashMap<>();
                error.put("message", "User not found with ID: " + userId);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
            }
        } catch (Exception e) {
            logger.error("Error activating user with ID {}: {}", userId, e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", "Error activating user");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    // Search users by email
    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN') or hasRole('CO_ADMIN') or hasRole('MANAGER')")
    public ResponseEntity<?> searchUsersByEmail(@RequestParam String email) {
        logger.info("Searching users by email: {}", email);

        try {
            UserResponse user = userService.getUserByEmail(email);
            if (user != null) {
                logger.info("Found user with email: {}", email);
                return ResponseEntity.ok(user);
            } else {
                logger.warn("No user found with email: {}", email);
                Map<String, String> message = new HashMap<>();
                message.put("message", "No user found with email: " + email);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(message);
            }
        } catch (Exception e) {
            logger.error("Error searching user by email {}: {}", email, e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", "Error searching user");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    // Get users by role
    @GetMapping("/role/{roleName}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('CO_ADMIN')")
    public ResponseEntity<List<UserResponse>> getUsersByRole(@PathVariable String roleName) {
        logger.info("Fetching users with role: {}", roleName);

        try {
            List<UserResponse> users = userService.getUsersByRole(roleName);
            logger.info("Found {} users with role: {}", users.size(), roleName);
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            logger.error("Error fetching users by role {}: {}", roleName, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // Count total users
    @GetMapping("/count")
    @PreAuthorize("hasRole('ADMIN') or hasRole('CO_ADMIN') or hasRole('MANAGER')")
    public ResponseEntity<Map<String, Long>> countUsers() {
        logger.info("Counting total users");

        try {
            long count = userService.countUsers();
            Map<String, Long> response = new HashMap<>();
            response.put("total", count);
            response.put("active", userService.countActiveUsers());
            response.put("inactive", userService.countInactiveUsers());
            logger.info("Total users count: {}", count);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error counting users: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
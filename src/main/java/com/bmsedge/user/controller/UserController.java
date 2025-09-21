package com.bmsedge.user.controller;

import com.bmsedge.user.dto.PagedResponse;
import com.bmsedge.user.dto.UserResponse;
import com.bmsedge.user.dto.UserUpdateRequest;
import com.bmsedge.user.service.UserService;
import com.bmsedge.user.util.SecurityUtils;
import jakarta.validation.Valid;
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
import org.springframework.validation.BindingResult;
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

    // Get all users with pagination - Admin, Co-Admin, or Manager only
    @GetMapping
    @PreAuthorize("@securityUtils.isManagerOrAbove()")
    public ResponseEntity<PagedResponse<UserResponse>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "ASC") String sortDirection) {

        Long currentUserId = SecurityUtils.getCurrentUserId().orElse(null);
        logger.info("User {} fetching all users - page: {}, size: {}", currentUserId, page, size);

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

    // Get all users without pagination
    @GetMapping("/all")
    @PreAuthorize("@securityUtils.isManagerOrAbove()")
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

    // Get user by ID - Users can get their own info, managers can get any
    @GetMapping("/{userId}")
    @PreAuthorize("@securityUtils.isManagerOrAbove() or @securityUtils.isCurrentUser(#userId)")
    public ResponseEntity<?> getUserById(@PathVariable Long userId) {
        Long currentUserId = SecurityUtils.getCurrentUserId().orElse(null);
        logger.info("User {} fetching user with ID: {}", currentUserId, userId);

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

    // Update user - Users can update themselves, admins can update anyone
    @PutMapping("/{userId}")
    @PreAuthorize("@securityUtils.isAdminOrCoAdmin() or @securityUtils.isCurrentUser(#userId)")
    public ResponseEntity<?> updateUser(
            @PathVariable Long userId,
            @Valid @RequestBody UserUpdateRequest updateRequest,
            BindingResult result) {

        Long currentUserId = SecurityUtils.getCurrentUserId().orElse(null);
        logger.info("User {} updating user {}", currentUserId, userId);

        if (result.hasErrors()) {
            Map<String, String> errors = new HashMap<>();
            result.getFieldErrors().forEach(error ->
                    errors.put(error.getField(), error.getDefaultMessage()));
            return ResponseEntity.badRequest().body(errors);
        }

        try {
            // Non-admins cannot update roles
            boolean isAdmin = SecurityUtils.hasRole("ADMIN") || SecurityUtils.hasRole("CO_ADMIN");
            boolean isSelfUpdate = currentUserId != null && currentUserId.equals(userId);

            if (!isAdmin && updateRequest.getRoles() != null && !updateRequest.getRoles().isEmpty()) {
                Map<String, String> error = new HashMap<>();
                error.put("message", "Only admins can update user roles");
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
            }

            UserResponse updatedUser = userService.updateUser(userId, updateRequest);
            if (updatedUser != null) {
                logger.info("User updated successfully: {}", updatedUser.getEmail());
                return ResponseEntity.ok(updatedUser);
            } else {
                logger.warn("User not found with ID: {}", userId);
                Map<String, String> error = new HashMap<>();
                error.put("message", "User not found with ID: " + userId);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
            }
        } catch (RuntimeException e) {
            logger.error("Error updating user: {}", e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        } catch (Exception e) {
            logger.error("Unexpected error updating user with ID {}: {}", userId, e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", "Error updating user");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    // Delete user by ID - Admin only
    @DeleteMapping("/{userId}")
    @PreAuthorize("@securityUtils.isAdmin()")
    public ResponseEntity<?> deleteUser(@PathVariable Long userId) {
        Long currentUserId = SecurityUtils.getCurrentUserId().orElse(null);
        logger.info("Admin {} attempting to delete user {}", currentUserId, userId);

        try {
            // Prevent self-deletion
            if (currentUserId != null && currentUserId.equals(userId)) {
                Map<String, String> error = new HashMap<>();
                error.put("message", "You cannot delete your own account");
                return ResponseEntity.badRequest().body(error);
            }

            boolean deleted = userService.deleteUser(userId);
            if (deleted) {
                logger.info("Successfully deleted user with ID: {}", userId);
                Map<String, String> response = new HashMap<>();
                response.put("message", "User deleted successfully");
                response.put("userId", userId.toString());
                return ResponseEntity.ok(response);
            } else {
                logger.warn("User not found with ID: {}", userId);
                Map<String, String> error = new HashMap<>();
                error.put("message", "User not found with ID: " + userId);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
            }
        } catch (RuntimeException e) {
            logger.error("Error deleting user: {}", e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        } catch (Exception e) {
            logger.error("Error deleting user with ID {}: {}", userId, e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", "Error deleting user: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    // Deactivate user - Admin or Co-Admin only
    @PutMapping("/{userId}/deactivate")
    @PreAuthorize("@securityUtils.isAdminOrCoAdmin()")
    public ResponseEntity<?> deactivateUser(@PathVariable Long userId) {
        Long currentUserId = SecurityUtils.getCurrentUserId().orElse(null);
        logger.info("User {} deactivating user {}", currentUserId, userId);

        try {
            // Prevent self-deactivation
            if (currentUserId != null && currentUserId.equals(userId)) {
                Map<String, String> error = new HashMap<>();
                error.put("message", "You cannot deactivate your own account");
                return ResponseEntity.badRequest().body(error);
            }

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
        } catch (RuntimeException e) {
            logger.error("Error deactivating user: {}", e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        } catch (Exception e) {
            logger.error("Error deactivating user with ID {}: {}", userId, e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", "Error deactivating user");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    // Activate user - Admin or Co-Admin only
    @PutMapping("/{userId}/activate")
    @PreAuthorize("@securityUtils.isAdminOrCoAdmin()")
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

    // Add role to user - Admin only
    @PostMapping("/{userId}/roles/{roleName}")
    @PreAuthorize("@securityUtils.isAdmin()")
    public ResponseEntity<?> addRoleToUser(@PathVariable Long userId, @PathVariable String roleName) {
        logger.info("Adding role {} to user {}", roleName, userId);

        try {
            UserResponse user = userService.addRoleToUser(userId, roleName);
            if (user != null) {
                logger.info("Successfully added role {} to user {}", roleName, userId);
                return ResponseEntity.ok(user);
            } else {
                logger.warn("User not found with ID: {}", userId);
                Map<String, String> error = new HashMap<>();
                error.put("message", "User not found with ID: " + userId);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
            }
        } catch (RuntimeException e) {
            logger.error("Error adding role: {}", e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        } catch (Exception e) {
            logger.error("Error adding role {} to user {}: {}", roleName, userId, e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", "Error adding role");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    // Remove role from user - Admin only
    @DeleteMapping("/{userId}/roles/{roleName}")
    @PreAuthorize("@securityUtils.isAdmin()")
    public ResponseEntity<?> removeRoleFromUser(@PathVariable Long userId, @PathVariable String roleName) {
        logger.info("Removing role {} from user {}", roleName, userId);

        try {
            UserResponse user = userService.removeRoleFromUser(userId, roleName);
            if (user != null) {
                logger.info("Successfully removed role {} from user {}", roleName, userId);
                return ResponseEntity.ok(user);
            } else {
                logger.warn("User not found with ID: {}", userId);
                Map<String, String> error = new HashMap<>();
                error.put("message", "User not found with ID: " + userId);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
            }
        } catch (RuntimeException e) {
            logger.error("Error removing role: {}", e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        } catch (Exception e) {
            logger.error("Error removing role {} from user {}: {}", roleName, userId, e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("message", "Error removing role");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    // Get current user profile - Any authenticated user
    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getCurrentUser() {
        try {
            Long userId = SecurityUtils.getCurrentUserId()
                    .orElseThrow(() -> new RuntimeException("User not authenticated"));

            UserResponse user = userService.getUserById(userId);
            if (user != null) {
                logger.info("Retrieved profile for current user: {}", user.getEmail());
                return ResponseEntity.ok(user);
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("message", "User profile not found"));
            }
        } catch (Exception e) {
            logger.error("Error fetching current user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Error fetching profile"));
        }
    }

    // Update current user profile - Any authenticated user
    @PutMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> updateCurrentUser(
            @Valid @RequestBody UserUpdateRequest updateRequest,
            BindingResult result) {

        try {
            Long userId = SecurityUtils.getCurrentUserId()
                    .orElseThrow(() -> new RuntimeException("User not authenticated"));

            // Users cannot change their own roles through this endpoint
            updateRequest.setRoles(null);
            updateRequest.setActive(null);  // Also prevent changing active status

            logger.info("User {} updating their own profile", userId);

            return updateUser(userId, updateRequest, result);
        } catch (Exception e) {
            logger.error("Error updating current user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Error updating profile"));
        }
    }

    // Search users by email - Manager or above
    @GetMapping("/search")
    @PreAuthorize("@securityUtils.isManagerOrAbove()")
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

    // Get users by role - Admin or Co-Admin only
    @GetMapping("/role/{roleName}")
    @PreAuthorize("@securityUtils.isAdminOrCoAdmin()")
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

    // Get active users - Manager or above
    @GetMapping("/status/active")
    @PreAuthorize("@securityUtils.isManagerOrAbove()")
    public ResponseEntity<List<UserResponse>> getActiveUsers() {
        logger.info("Fetching active users");

        try {
            List<UserResponse> users = userService.getActiveUsers();
            logger.info("Found {} active users", users.size());
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            logger.error("Error fetching active users: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // Get inactive users - Admin or Co-Admin only
    @GetMapping("/status/inactive")
    @PreAuthorize("@securityUtils.isAdminOrCoAdmin()")
    public ResponseEntity<List<UserResponse>> getInactiveUsers() {
        logger.info("Fetching inactive users");

        try {
            List<UserResponse> users = userService.getInactiveUsers();
            logger.info("Found {} inactive users", users.size());
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            logger.error("Error fetching inactive users: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // Count total users - Manager or above
    @GetMapping("/count")
    @PreAuthorize("@securityUtils.isManagerOrAbove()")
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
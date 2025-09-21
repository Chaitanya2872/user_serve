package com.bmsedge.user.service;

import com.bmsedge.user.dto.UserResponse;
import com.bmsedge.user.dto.UserUpdateRequest;
import com.bmsedge.user.model.Role;
import com.bmsedge.user.model.User;
import com.bmsedge.user.repository.UserRepository;
import com.bmsedge.user.security.UserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Transactional
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // Convert User entity to UserResponse DTO
    private UserResponse convertToUserResponse(User user) {
        UserResponse response = new UserResponse();
        response.setId(user.getId());
        response.setFullName(user.getFullName());
        response.setEmail(user.getEmail());
        response.setActive(user.isActive());
        response.setLastLogin(user.getLastLogin());
        response.setCreatedAt(user.getCreatedAt());
        response.setUpdatedAt(user.getUpdatedAt());

        // Convert Role enum set to String set
        Set<String> roleStrings = user.getRoles().stream()
                .map(Role::name)
                .collect(Collectors.toSet());
        response.setRoles(roleStrings);

        return response;
    }

    // Get current logged-in user
    private Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserPrincipal) {
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            return userPrincipal.getId();
        }
        return null;
    }

    // Check if current user has admin role
    private boolean isCurrentUserAdmin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            return authentication.getAuthorities().stream()
                    .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
        }
        return false;
    }

    // Get all users with pagination
    public Page<UserResponse> getAllUsers(Pageable pageable) {
        logger.info("Fetching users with pagination");
        try {
            Page<User> usersPage = userRepository.findAll(pageable);
            return usersPage.map(this::convertToUserResponse);
        } catch (Exception e) {
            logger.error("Error fetching users: {}", e.getMessage());
            throw new RuntimeException("Failed to fetch users", e);
        }
    }

    // Get all users without pagination
    public List<UserResponse> getAllUsersNoPaging() {
        logger.info("Fetching all users without pagination");
        try {
            List<User> users = userRepository.findAll();
            return users.stream()
                    .map(this::convertToUserResponse)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            logger.error("Error fetching users: {}", e.getMessage());
            throw new RuntimeException("Failed to fetch users", e);
        }
    }

    // Get user by ID
    public UserResponse getUserById(Long userId) {
        logger.info("Fetching user with ID: {}", userId);
        try {
            Optional<User> userOpt = userRepository.findById(userId);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                logger.info("User found: {}", user.getEmail());
                return convertToUserResponse(user);
            } else {
                logger.warn("User not found with ID: {}", userId);
                return null;
            }
        } catch (Exception e) {
            logger.error("Error fetching user with ID {}: {}", userId, e.getMessage());
            throw new RuntimeException("Failed to fetch user", e);
        }
    }

    // Get user by email
    public UserResponse getUserByEmail(String email) {
        logger.info("Fetching user with email: {}", email);
        try {
            Optional<User> userOpt = userRepository.findByEmail(email);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                logger.info("User found with email: {}", email);
                return convertToUserResponse(user);
            } else {
                logger.warn("User not found with email: {}", email);
                return null;
            }
        } catch (Exception e) {
            logger.error("Error fetching user with email {}: {}", email, e.getMessage());
            throw new RuntimeException("Failed to fetch user", e);
        }
    }

    // Delete user by ID (hard delete) - Enhanced with proper admin logic
    public boolean deleteUser(Long userId) {
        logger.info("Attempting to delete user with ID: {}", userId);

        try {
            // Get current user ID
            Long currentUserId = getCurrentUserId();

            // Prevent self-deletion
            if (currentUserId != null && currentUserId.equals(userId)) {
                logger.error("User cannot delete themselves. User ID: {}", userId);
                throw new RuntimeException("You cannot delete your own account");
            }

            Optional<User> userOpt = userRepository.findById(userId);
            if (userOpt.isPresent()) {
                User userToDelete = userOpt.get();

                // Check if trying to delete another admin
                boolean isTargetAdmin = userToDelete.getRoles().contains(Role.ADMIN);

                if (isTargetAdmin) {
                    // Count total active admins
                    long adminCount = userRepository.findByRole(Role.ADMIN).stream()
                            .filter(User::isActive)
                            .count();

                    if (adminCount <= 1) {
                        logger.error("Cannot delete the last admin user");
                        throw new RuntimeException("Cannot delete the last admin user in the system");
                    }

                    // Only allow admin deletion if current user is also an admin
                    if (!isCurrentUserAdmin()) {
                        logger.error("Non-admin trying to delete admin user");
                        throw new RuntimeException("Only admins can delete other admin users");
                    }

                    logger.warn("Admin user {} is deleting another admin user: {}", currentUserId, userToDelete.getEmail());
                }

                logger.info("Deleting user: {}", userToDelete.getEmail());
                userRepository.deleteById(userId);
                logger.info("User deleted successfully: {}", userToDelete.getEmail());
                return true;
            } else {
                logger.warn("User not found with ID: {}", userId);
                return false;
            }
        } catch (RuntimeException e) {
            throw e; // Re-throw runtime exceptions
        } catch (Exception e) {
            logger.error("Error deleting user with ID {}: {}", userId, e.getMessage());
            throw new RuntimeException("Failed to delete user: " + e.getMessage(), e);
        }
    }

    // Soft delete (deactivate) user - Enhanced
    public UserResponse deactivateUser(Long userId) {
        logger.info("Attempting to deactivate user with ID: {}", userId);

        try {
            // Get current user ID
            Long currentUserId = getCurrentUserId();

            // Prevent self-deactivation
            if (currentUserId != null && currentUserId.equals(userId)) {
                logger.error("User cannot deactivate themselves. User ID: {}", userId);
                throw new RuntimeException("You cannot deactivate your own account");
            }

            Optional<User> userOpt = userRepository.findById(userId);
            if (userOpt.isPresent()) {
                User user = userOpt.get();

                // Check if trying to deactivate an admin
                if (user.getRoles().contains(Role.ADMIN)) {
                    // Count active admins
                    long activeAdminCount = userRepository.findByRole(Role.ADMIN).stream()
                            .filter(User::isActive)
                            .count();

                    if (activeAdminCount <= 1) {
                        logger.error("Cannot deactivate the last active admin");
                        throw new RuntimeException("Cannot deactivate the last active admin in the system");
                    }
                }

                user.setActive(false);
                user.setUpdatedAt(LocalDateTime.now());
                User savedUser = userRepository.save(user);
                logger.info("User deactivated successfully: {}", savedUser.getEmail());
                return convertToUserResponse(savedUser);
            } else {
                logger.warn("User not found with ID: {}", userId);
                return null;
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Error deactivating user with ID {}: {}", userId, e.getMessage());
            throw new RuntimeException("Failed to deactivate user: " + e.getMessage(), e);
        }
    }

    // Reactivate user
    public UserResponse activateUser(Long userId) {
        logger.info("Attempting to activate user with ID: {}", userId);
        try {
            Optional<User> userOpt = userRepository.findById(userId);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                user.setActive(true);
                user.setUpdatedAt(LocalDateTime.now());
                User savedUser = userRepository.save(user);
                logger.info("User activated successfully: {}", savedUser.getEmail());
                return convertToUserResponse(savedUser);
            } else {
                logger.warn("User not found with ID: {}", userId);
                return null;
            }
        } catch (Exception e) {
            logger.error("Error activating user with ID {}: {}", userId, e.getMessage());
            throw new RuntimeException("Failed to activate user", e);
        }
    }

    // Get users by role
    public List<UserResponse> getUsersByRole(String roleName) {
        logger.info("Fetching users with role: {}", roleName);
        try {
            Role role = Role.valueOf(roleName.toUpperCase());
            List<User> users = userRepository.findByRolesContaining(role);
            return users.stream()
                    .map(this::convertToUserResponse)
                    .collect(Collectors.toList());
        } catch (IllegalArgumentException e) {
            logger.error("Invalid role name: {}", roleName);
            throw new RuntimeException("Invalid role: " + roleName);
        } catch (Exception e) {
            logger.error("Error fetching users by role {}: {}", roleName, e.getMessage());
            throw new RuntimeException("Failed to fetch users by role", e);
        }
    }

    // Get active users
    public List<UserResponse> getActiveUsers() {
        logger.info("Fetching active users");
        try {
            List<User> users = userRepository.findByActive(true);
            return users.stream()
                    .map(this::convertToUserResponse)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            logger.error("Error fetching active users: {}", e.getMessage());
            throw new RuntimeException("Failed to fetch active users", e);
        }
    }

    // Get inactive users
    public List<UserResponse> getInactiveUsers() {
        logger.info("Fetching inactive users");
        try {
            List<User> users = userRepository.findByActive(false);
            return users.stream()
                    .map(this::convertToUserResponse)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            logger.error("Error fetching inactive users: {}", e.getMessage());
            throw new RuntimeException("Failed to fetch inactive users", e);
        }
    }

    // Count total users
    public long countUsers() {
        logger.info("Counting total users");
        try {
            return userRepository.count();
        } catch (Exception e) {
            logger.error("Error counting users: {}", e.getMessage());
            throw new RuntimeException("Failed to count users", e);
        }
    }

    // Count active users
    public long countActiveUsers() {
        logger.info("Counting active users");
        try {
            return userRepository.countByActive(true);
        } catch (Exception e) {
            logger.error("Error counting active users: {}", e.getMessage());
            throw new RuntimeException("Failed to count active users", e);
        }
    }

    // Count inactive users
    public long countInactiveUsers() {
        logger.info("Counting inactive users");
        try {
            return userRepository.countByActive(false);
        } catch (Exception e) {
            logger.error("Error counting inactive users: {}", e.getMessage());
            throw new RuntimeException("Failed to count inactive users", e);
        }
    }

    // Update user - Enhanced with proper validation
    public UserResponse updateUser(Long userId, UserUpdateRequest updateRequest) {
        logger.info("Updating user with ID: {}", userId);

        try {
            Optional<User> userOpt = userRepository.findById(userId);
            if (!userOpt.isPresent()) {
                logger.warn("User not found with ID: {}", userId);
                return null;
            }

            User existingUser = userOpt.get();
            Long currentUserId = getCurrentUserId();
            boolean isUpdatingSelf = currentUserId != null && currentUserId.equals(userId);
            boolean isAdmin = isCurrentUserAdmin();

            // Update basic fields
            if (updateRequest.getFullName() != null) {
                existingUser.setFullName(updateRequest.getFullName());
            }

            // Update email if provided and not already taken
            if (updateRequest.getEmail() != null && !updateRequest.getEmail().equals(existingUser.getEmail())) {
                if (userRepository.existsByEmail(updateRequest.getEmail())) {
                    throw new RuntimeException("Email already taken: " + updateRequest.getEmail());
                }
                existingUser.setEmail(updateRequest.getEmail());
            }

            // Update password if provided
            if (updateRequest.getPassword() != null && !updateRequest.getPassword().isEmpty()) {
                existingUser.setPassword(passwordEncoder.encode(updateRequest.getPassword()));
            }

            // Update roles - only admins can update roles, and users can't update their own roles
            if (updateRequest.getRoles() != null && !updateRequest.getRoles().isEmpty()) {
                if (!isAdmin) {
                    throw new RuntimeException("Only admins can update user roles");
                }
                if (isUpdatingSelf) {
                    throw new RuntimeException("You cannot modify your own roles");
                }

                // Prevent removing the last admin
                if (existingUser.getRoles().contains(Role.ADMIN) && !updateRequest.getRoles().contains(Role.ADMIN)) {
                    long adminCount = userRepository.findByRole(Role.ADMIN).stream()
                            .filter(User::isActive)
                            .count();
                    if (adminCount <= 1) {
                        throw new RuntimeException("Cannot remove admin role from the last admin user");
                    }
                }

                existingUser.setRoles(updateRequest.getRoles());
            }

            existingUser.setUpdatedAt(LocalDateTime.now());
            User savedUser = userRepository.save(existingUser);

            logger.info("User updated successfully: {}", savedUser.getEmail());
            return convertToUserResponse(savedUser);

        } catch (RuntimeException e) {
            logger.error("Error updating user: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Error updating user with ID {}: {}", userId, e.getMessage());
            throw new RuntimeException("Failed to update user: " + e.getMessage(), e);
        }
    }

    // Add user to role
    public UserResponse addRoleToUser(Long userId, String roleName) {
        logger.info("Adding role {} to user {}", roleName, userId);

        try {
            Optional<User> userOpt = userRepository.findById(userId);
            if (!userOpt.isPresent()) {
                logger.warn("User not found with ID: {}", userId);
                return null;
            }

            User user = userOpt.get();
            Role role = Role.valueOf(roleName.toUpperCase());

            // Check permissions
            Long currentUserId = getCurrentUserId();
            if (currentUserId != null && currentUserId.equals(userId)) {
                throw new RuntimeException("You cannot modify your own roles");
            }

            if (!isCurrentUserAdmin()) {
                throw new RuntimeException("Only admins can modify user roles");
            }

            user.getRoles().add(role);
            user.setUpdatedAt(LocalDateTime.now());
            User savedUser = userRepository.save(user);

            logger.info("Role {} added to user {}", roleName, user.getEmail());
            return convertToUserResponse(savedUser);

        } catch (IllegalArgumentException e) {
            logger.error("Invalid role name: {}", roleName);
            throw new RuntimeException("Invalid role: " + roleName);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Error adding role to user: {}", e.getMessage());
            throw new RuntimeException("Failed to add role: " + e.getMessage(), e);
        }
    }

    // Remove role from user
    public UserResponse removeRoleFromUser(Long userId, String roleName) {
        logger.info("Removing role {} from user {}", roleName, userId);

        try {
            Optional<User> userOpt = userRepository.findById(userId);
            if (!userOpt.isPresent()) {
                logger.warn("User not found with ID: {}", userId);
                return null;
            }

            User user = userOpt.get();
            Role role = Role.valueOf(roleName.toUpperCase());

            // Check permissions
            Long currentUserId = getCurrentUserId();
            if (currentUserId != null && currentUserId.equals(userId)) {
                throw new RuntimeException("You cannot modify your own roles");
            }

            if (!isCurrentUserAdmin()) {
                throw new RuntimeException("Only admins can modify user roles");
            }

            // Prevent removing the last admin
            if (role == Role.ADMIN && user.getRoles().contains(Role.ADMIN)) {
                long adminCount = userRepository.findByRole(Role.ADMIN).stream()
                        .filter(User::isActive)
                        .count();
                if (adminCount <= 1) {
                    throw new RuntimeException("Cannot remove admin role from the last admin user");
                }
            }

            user.getRoles().remove(role);

            // Ensure user has at least one role
            if (user.getRoles().isEmpty()) {
                user.getRoles().add(Role.USER);
            }

            user.setUpdatedAt(LocalDateTime.now());
            User savedUser = userRepository.save(user);

            logger.info("Role {} removed from user {}", roleName, user.getEmail());
            return convertToUserResponse(savedUser);

        } catch (IllegalArgumentException e) {
            logger.error("Invalid role name: {}", roleName);
            throw new RuntimeException("Invalid role: " + roleName);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Error removing role from user: {}", e.getMessage());
            throw new RuntimeException("Failed to remove role: " + e.getMessage(), e);
        }
    }

    // Check if user exists by email
    public boolean userExistsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    // Check if user exists by ID
    public boolean userExistsById(Long userId) {
        return userRepository.existsById(userId);
    }
}
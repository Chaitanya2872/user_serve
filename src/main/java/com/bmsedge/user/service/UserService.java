package com.bmsedge.user.service;

import com.bmsedge.user.dto.UserResponse;
import com.bmsedge.user.model.Role;
import com.bmsedge.user.model.User;
import com.bmsedge.user.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
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

    // Delete user by ID (hard delete)
    public boolean deleteUser(Long userId) {
        logger.info("Attempting to delete user with ID: {}", userId);
        try {
            Optional<User> userOpt = userRepository.findById(userId);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                logger.info("Deleting user: {}", user.getEmail());
                userRepository.deleteById(userId);
                logger.info("User deleted successfully: {}", user.getEmail());
                return true;
            } else {
                logger.warn("User not found with ID: {}", userId);
                return false;
            }
        } catch (Exception e) {
            logger.error("Error deleting user with ID {}: {}", userId, e.getMessage());
            throw new RuntimeException("Failed to delete user", e);
        }
    }

    // Soft delete (deactivate) user
    public UserResponse deactivateUser(Long userId) {
        logger.info("Attempting to deactivate user with ID: {}", userId);
        try {
            Optional<User> userOpt = userRepository.findById(userId);
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                user.setActive(false);
                user.setUpdatedAt(LocalDateTime.now());
                User savedUser = userRepository.save(user);
                logger.info("User deactivated successfully: {}", savedUser.getEmail());
                return convertToUserResponse(savedUser);
            } else {
                logger.warn("User not found with ID: {}", userId);
                return null;
            }
        } catch (Exception e) {
            logger.error("Error deactivating user with ID {}: {}", userId, e.getMessage());
            throw new RuntimeException("Failed to deactivate user", e);
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

    // Update user
    public UserResponse updateUser(Long userId, User updatedUser) {
        logger.info("Updating user with ID: {}", userId);
        try {
            Optional<User> userOpt = userRepository.findById(userId);
            if (userOpt.isPresent()) {
                User existingUser = userOpt.get();

                // Update fields
                if (updatedUser.getFullName() != null) {
                    existingUser.setFullName(updatedUser.getFullName());
                }
                if (updatedUser.getRoles() != null && !updatedUser.getRoles().isEmpty()) {
                    existingUser.setRoles(updatedUser.getRoles());
                }

                existingUser.setUpdatedAt(LocalDateTime.now());
                User savedUser = userRepository.save(existingUser);

                logger.info("User updated successfully: {}", savedUser.getEmail());
                return convertToUserResponse(savedUser);
            } else {
                logger.warn("User not found with ID: {}", userId);
                return null;
            }
        } catch (Exception e) {
            logger.error("Error updating user with ID {}: {}", userId, e.getMessage());
            throw new RuntimeException("Failed to update user", e);
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
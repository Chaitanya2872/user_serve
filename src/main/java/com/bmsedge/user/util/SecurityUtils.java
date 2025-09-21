package com.bmsedge.user.util;

import com.bmsedge.user.security.UserPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Utility class for security-related operations.
 * Provides methods to access the current authenticated user's information.
 */
@Component("securityUtils")
public class SecurityUtils {

    /**
     * Get the current authenticated user's ID (static method)
     * @return Optional containing the user ID if authenticated, empty otherwise
     */
    public static Optional<Long> getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.getPrincipal() instanceof UserPrincipal) {
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            return Optional.of(userPrincipal.getId());
        }

        return Optional.empty();
    }

    /**
     * Get the current authenticated user's email
     * @return Optional containing the user email if authenticated, empty otherwise
     */
    public static Optional<String> getCurrentUserEmail() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.getPrincipal() instanceof UserPrincipal) {
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            return Optional.of(userPrincipal.getEmail());
        }

        return Optional.empty();
    }

    /**
     * Get the current authenticated user's full name
     * @return Optional containing the user's full name if authenticated, empty otherwise
     */
    public static Optional<String> getCurrentUserFullName() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.getPrincipal() instanceof UserPrincipal) {
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            return Optional.of(userPrincipal.getFullName());
        }

        return Optional.empty();
    }

    /**
     * Get the current UserPrincipal
     * @return Optional containing the UserPrincipal if authenticated, empty otherwise
     */
    public static Optional<UserPrincipal> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.getPrincipal() instanceof UserPrincipal) {
            return Optional.of((UserPrincipal) authentication.getPrincipal());
        }

        return Optional.empty();
    }

    /**
     * Check if current user is authenticated
     * @return true if user is authenticated, false otherwise
     */
    public static boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.isAuthenticated()
                && authentication.getPrincipal() instanceof UserPrincipal;
    }

    /**
     * Check if current user has a specific role
     * @param role The role to check (without ROLE_ prefix)
     * @return true if user has the role, false otherwise
     */
    public static boolean hasRole(String role) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            String roleWithPrefix = role.startsWith("ROLE_") ? role : "ROLE_" + role;
            return authentication.getAuthorities().stream()
                    .anyMatch(auth -> auth.getAuthority().equals(roleWithPrefix));
        }

        return false;
    }

    /**
     * Check if current user has any of the specified roles
     * @param roles The roles to check (without ROLE_ prefix)
     * @return true if user has any of the roles, false otherwise
     */
    public static boolean hasAnyRole(String... roles) {
        for (String role : roles) {
            if (hasRole(role)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if current user has all of the specified roles
     * @param roles The roles to check (without ROLE_ prefix)
     * @return true if user has all of the roles, false otherwise
     */
    public static boolean hasAllRoles(String... roles) {
        for (String role : roles) {
            if (!hasRole(role)) {
                return false;
            }
        }
        return roles.length > 0 && isAuthenticated();
    }

    // ===== NON-STATIC METHODS FOR SPRING EXPRESSION LANGUAGE (SpEL) =====
    // These methods are for use with @PreAuthorize annotations
    // They delegate to the static methods but are instance methods

    /**
     * Instance method to get current user ID for SpEL expressions
     * Used in @PreAuthorize annotations
     */
    public Long getCurrentUserIdForAuth() {
        return getCurrentUserId().orElse(null);
    }

    /**
     * Instance method to check if the current user matches the given ID
     * Used in @PreAuthorize annotations
     */
    public boolean isCurrentUser(Long userId) {
        if (userId == null) {
            return false;
        }
        return getCurrentUserId()
                .map(currentId -> currentId.equals(userId))
                .orElse(false);
    }

    /**
     * Instance method to check if current user is admin
     * Used in @PreAuthorize annotations
     */
    public boolean isAdmin() {
        return hasRole("ADMIN");
    }

    /**
     * Instance method to check if current user is admin or co-admin
     * Used in @PreAuthorize annotations
     */
    public boolean isAdminOrCoAdmin() {
        return hasAnyRole("ADMIN", "CO_ADMIN");
    }

    /**
     * Instance method to check if current user is manager or above
     * Used in @PreAuthorize annotations
     */
    public boolean isManagerOrAbove() {
        return hasAnyRole("ADMIN", "CO_ADMIN", "MANAGER");
    }
}
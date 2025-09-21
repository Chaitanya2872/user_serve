package com.bmsedge.user.repository;

import com.bmsedge.user.model.Role;
import com.bmsedge.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    Boolean existsByEmail(String email);

    // Find users by active status
    List<User> findByActive(boolean active);

    // Find users by role - corrected for @ElementCollection
    @Query("SELECT DISTINCT u FROM User u JOIN u.roles r WHERE r = :role")
    List<User> findByRolesContaining(@Param("role") Role role);

    // Alternative method using member of
    @Query("SELECT u FROM User u WHERE :role MEMBER OF u.roles")
    List<User> findByRole(@Param("role") Role role);

    // Find users having any of the specified roles
    @Query("SELECT DISTINCT u FROM User u JOIN u.roles r WHERE r IN :roles")
    List<User> findByRolesIn(@Param("roles") List<Role> roles);

    // Count users by active status
    Long countByActive(boolean active);

    // Count users by role
    @Query("SELECT COUNT(DISTINCT u) FROM User u JOIN u.roles r WHERE r = :role")
    Long countByRole(@Param("role") Role role);

    // Find active users with specific role
    @Query("SELECT DISTINCT u FROM User u JOIN u.roles r WHERE u.active = :active AND r = :role")
    List<User> findByActiveAndRole(@Param("active") boolean active, @Param("role") Role role);

    // Check if user exists by ID (this is already provided by JpaRepository, but we can keep it explicit)
    boolean existsById(Long id);
}
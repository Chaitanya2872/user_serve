package com.bmsedge.user.config;

import com.bmsedge.user.model.Role;
import com.bmsedge.user.model.User;
import com.bmsedge.user.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Configuration
public class DataInitializer {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    CommandLineRunner initDatabase(UserRepository userRepository) {
        return args -> {
            // Create primary admin user
            if (!userRepository.existsByEmail("admin@bmsedge.com")) {
                User adminUser = new User();
                adminUser.setFullName("System Administrator");
                adminUser.setEmail("admin@bmsedge.com");
                adminUser.setPassword(passwordEncoder.encode("admin123"));
                adminUser.setActive(true);
                adminUser.setCreatedAt(LocalDateTime.now());
                adminUser.setUpdatedAt(LocalDateTime.now());

                Set<Role> adminRoles = new HashSet<>();
                adminRoles.add(Role.ADMIN);
                adminRoles.add(Role.USER);
                adminUser.setRoles(adminRoles);

                userRepository.save(adminUser);
                logger.info("Primary admin user created: admin@bmsedge.com / admin123");
            }

            // Create secondary admin user (for testing admin deletion)
            if (!userRepository.existsByEmail("admin2@bmsedge.com")) {
                User admin2User = new User();
                admin2User.setFullName("Secondary Administrator");
                admin2User.setEmail("admin2@bmsedge.com");
                admin2User.setPassword(passwordEncoder.encode("admin123"));
                admin2User.setActive(true);
                admin2User.setCreatedAt(LocalDateTime.now());
                admin2User.setUpdatedAt(LocalDateTime.now());

                Set<Role> admin2Roles = new HashSet<>();
                admin2Roles.add(Role.ADMIN);
                admin2Roles.add(Role.USER);
                admin2User.setRoles(admin2Roles);

                userRepository.save(admin2User);
                logger.info("Secondary admin user created: admin2@bmsedge.com / admin123");
            }

            // Create co-admin user
            if (!userRepository.existsByEmail("coadmin@bmsedge.com")) {
                User coAdminUser = new User();
                coAdminUser.setFullName("Co-Administrator");
                coAdminUser.setEmail("coadmin@bmsedge.com");
                coAdminUser.setPassword(passwordEncoder.encode("coadmin123"));
                coAdminUser.setActive(true);
                coAdminUser.setCreatedAt(LocalDateTime.now());
                coAdminUser.setUpdatedAt(LocalDateTime.now());

                Set<Role> coAdminRoles = new HashSet<>();
                coAdminRoles.add(Role.CO_ADMIN);
                coAdminRoles.add(Role.USER);
                coAdminUser.setRoles(coAdminRoles);

                userRepository.save(coAdminUser);
                logger.info("Co-admin user created: coadmin@bmsedge.com / coadmin123");
            }

            // Create a test manager user
            if (!userRepository.existsByEmail("manager@bmsedge.com")) {
                User managerUser = new User();
                managerUser.setFullName("Test Manager");
                managerUser.setEmail("manager@bmsedge.com");
                managerUser.setPassword(passwordEncoder.encode("manager123"));
                managerUser.setActive(true);
                managerUser.setCreatedAt(LocalDateTime.now());
                managerUser.setUpdatedAt(LocalDateTime.now());

                Set<Role> managerRoles = new HashSet<>();
                managerRoles.add(Role.MANAGER);
                managerRoles.add(Role.USER);
                managerUser.setRoles(managerRoles);

                userRepository.save(managerUser);
                logger.info("Manager user created: manager@bmsedge.com / manager123");
            }

            // Create regular test users
            if (!userRepository.existsByEmail("user@bmsedge.com")) {
                User regularUser = new User();
                regularUser.setFullName("Test User");
                regularUser.setEmail("user@bmsedge.com");
                regularUser.setPassword(passwordEncoder.encode("user123"));
                regularUser.setActive(true);
                regularUser.setCreatedAt(LocalDateTime.now());
                regularUser.setUpdatedAt(LocalDateTime.now());

                Set<Role> userRoles = new HashSet<>();
                userRoles.add(Role.USER);
                regularUser.setRoles(userRoles);

                userRepository.save(regularUser);
                logger.info("Regular user created: user@bmsedge.com / user123");
            }

            // Create another regular user for deletion testing
            if (!userRepository.existsByEmail("john.doe@example.com")) {
                User johnUser = new User();
                johnUser.setFullName("John Doe");
                johnUser.setEmail("john.doe@example.com");
                johnUser.setPassword(passwordEncoder.encode("password123"));
                johnUser.setActive(true);
                johnUser.setCreatedAt(LocalDateTime.now());
                johnUser.setUpdatedAt(LocalDateTime.now());

                Set<Role> johnRoles = new HashSet<>();
                johnRoles.add(Role.USER);
                johnUser.setRoles(johnRoles);

                userRepository.save(johnUser);
                logger.info("Test user created: john.doe@example.com / password123");
            }

            // Create inactive user for testing
            if (!userRepository.existsByEmail("inactive@bmsedge.com")) {
                User inactiveUser = new User();
                inactiveUser.setFullName("Inactive User");
                inactiveUser.setEmail("inactive@bmsedge.com");
                inactiveUser.setPassword(passwordEncoder.encode("inactive123"));
                inactiveUser.setActive(false);
                inactiveUser.setCreatedAt(LocalDateTime.now());
                inactiveUser.setUpdatedAt(LocalDateTime.now());

                Set<Role> inactiveRoles = new HashSet<>();
                inactiveRoles.add(Role.USER);
                inactiveUser.setRoles(inactiveRoles);

                userRepository.save(inactiveUser);
                logger.info("Inactive user created: inactive@bmsedge.com / inactive123");
            }

            logger.info("===========================================");
            logger.info("Test users created successfully!");
            logger.info("===========================================");
            logger.info("ADMIN USERS:");
            logger.info("  Primary Admin: admin@bmsedge.com / admin123");
            logger.info("  Secondary Admin: admin2@bmsedge.com / admin123");
            logger.info("CO-ADMIN USER:");
            logger.info("  Co-Admin: coadmin@bmsedge.com / coadmin123");
            logger.info("MANAGER USER:");
            logger.info("  Manager: manager@bmsedge.com / manager123");
            logger.info("REGULAR USERS:");
            logger.info("  User 1: user@bmsedge.com / user123");
            logger.info("  User 2: john.doe@example.com / password123");
            logger.info("INACTIVE USER:");
            logger.info("  Inactive: inactive@bmsedge.com / inactive123");
            logger.info("===========================================");

            // Display user counts
            long totalUsers = userRepository.count();
            long activeUsers = userRepository.countByActive(true);
            long inactiveUsers = userRepository.countByActive(false);
            long adminCount = userRepository.findByRole(Role.ADMIN).size();

            logger.info("User Statistics:");
            logger.info("  Total Users: {}", totalUsers);
            logger.info("  Active Users: {}", activeUsers);
            logger.info("  Inactive Users: {}", inactiveUsers);
            logger.info("  Admin Users: {}", adminCount);
            logger.info("===========================================");
        };
    }
}
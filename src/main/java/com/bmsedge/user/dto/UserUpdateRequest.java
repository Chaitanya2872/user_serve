package com.bmsedge.user.dto;

import com.bmsedge.user.model.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import java.util.Set;

public class UserUpdateRequest {

    @Size(min = 3, max = 100)
    private String fullName;

    @Email
    @Size(max = 150)
    private String email;

    @Size(min = 6, max = 120)
    private String password;

    private Set<Role> roles;

    private Boolean active;

    // Constructors
    public UserUpdateRequest() {}

    public UserUpdateRequest(String fullName, String email, String password, Set<Role> roles, Boolean active) {
        this.fullName = fullName;
        this.email = email;
        this.password = password;
        this.roles = roles;
        this.active = active;
    }

    // Getters and Setters
    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }
}
package com.secur.securite.service;

import com.secur.securite.entities.AppRole;
import com.secur.securite.entities.AppUser;

public interface AccountService {
    public AppUser saveUser(AppUser user);
    public AppRole saveRole(AppRole role);
    public void addRoleToUser(String username,String roleName);
    public AppUser findUserByUsername(String username);
    public void deleteUsers();
    public void deleteRoles();
    
}

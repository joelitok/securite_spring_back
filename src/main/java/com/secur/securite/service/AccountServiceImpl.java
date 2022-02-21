package com.secur.securite.service;

import com.secur.securite.dao.RoleRepository;
import com.secur.securite.dao.UserRepository;
import com.secur.securite.entities.AppRole;
import com.secur.securite.entities.AppUser;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class AccountServiceImpl implements AccountService{
    
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RoleRepository roleRepository;

    
    
    @Override
    public AppUser saveUser(AppUser user) {
      String hashPW =bCryptPasswordEncoder.encode(user.getPassword());
      user.setPassword(hashPW);  
      return userRepository.save(user);
    }

    @Override
    public AppRole saveRole(AppRole role) {
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
     AppRole role = roleRepository.findByRoleName(roleName);
     AppUser user =userRepository.findByUsername(username);
     user.getRoles().add(role);   
    }

     @Override
     public AppUser findUserByUsername(String username) {
        return userRepository.findByUsername(username);
        
    }

    @Override
    public void deleteUsers() {
        userRepository.deleteAll();  
    }

    @Override
    public void deleteRoles() {
        roleRepository.deleteAll();
    }
    
}

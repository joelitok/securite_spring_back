package com.secur.securite.dao;

import com.secur.securite.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends JpaRepository<AppUser,Long>{
    public AppUser  findByUsername(String username);
}

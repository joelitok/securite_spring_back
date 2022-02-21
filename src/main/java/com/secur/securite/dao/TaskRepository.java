package com.secur.securite.dao;

import com.secur.securite.entities.Task;

import org.springframework.data.jpa.repository.JpaRepository;

public interface TaskRepository extends JpaRepository <Task,Long> {
    
}

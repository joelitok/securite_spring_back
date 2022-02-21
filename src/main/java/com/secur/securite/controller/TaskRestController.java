package com.secur.securite.controller;

import java.util.List;

import com.secur.securite.dao.TaskRepository;
import com.secur.securite.entities.Task;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin("*")
@RestController
public class TaskRestController{
    @Autowired
    private TaskRepository taskRepository;

    @GetMapping("/tasks")
    public List<Task> listTask(){
        return taskRepository.findAll();
    }
    
    @PostMapping("/tasks")
    
    //possible grace a l'annotation  @EnableGlobalMethodSecurity(prePostEnabled=true,securedEnabled=true) activer dans le fichier principal
    //@PostAuthorize("hasAuthority('ADMIN')")
    public Task save(@RequestBody Task t){
        return taskRepository.save(t);
    }
    
    
}

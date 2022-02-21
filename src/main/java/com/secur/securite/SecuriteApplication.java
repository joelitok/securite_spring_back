package com.secur.securite;


import com.secur.securite.dao.TaskRepository;
import com.secur.securite.entities.AppRole;
import com.secur.securite.entities.AppUser;
import com.secur.securite.entities.Task;
import com.secur.securite.service.AccountService;

import java.util.stream.Stream;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


@SpringBootApplication
//si vous vouler proteger les ressource, vous pouvez activer les parametre de securiter global
//@EnableGlobalMethodSecurity(prePostEnabled=true,securedEnabled=true)
public class SecuriteApplication implements CommandLineRunner{
  
@Autowired
private TaskRepository taskRepository;
@Autowired
private AccountService accountService;


	public static void main(String[] args) {
		SpringApplication.run(SecuriteApplication.class, args);
	}

	@Bean
	public BCryptPasswordEncoder getBCPE(){
		return new BCryptPasswordEncoder();
	}

   @Override
   public void run(String... args) throws Exception{
   
   accountService.deleteUsers();   
   accountService.saveUser(new AppUser(null,"admin","1234",null));
   accountService.saveUser(new AppUser(null,"user","1234",null));

   accountService.deleteRoles();
   accountService.saveRole(new AppRole(null,"ADMIN"));
   accountService.saveRole(new AppRole(null,"USER"));

   accountService.addRoleToUser("admin", "ADMIN");
  /* accountService.addRoleToUser("admin", "USER");*/
   accountService.addRoleToUser("user", "USER");
       
      taskRepository.deleteAll();
      Stream.of("T1","T2","T3").forEach(t->{
		  taskRepository.save(new Task(null,t));
	  }); 

        taskRepository.findAll().forEach(t->{
			System.out.println(t.getTaskName());
		});
    }

}

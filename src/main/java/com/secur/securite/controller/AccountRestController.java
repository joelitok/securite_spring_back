package com.secur.securite.controller;



import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.secur.securite.entities.AppUser;
import com.secur.securite.service.AccountService;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin("*")
@RestController
public class AccountRestController {
  @Autowired  
  private AccountService accountService;
 
/*
  @PostMapping("/register")
  public AppUser register(@RequestBody AppUser user){
      return  accountService.saveUser(user);
  }*/

  //enregistrer un utilisateur
  @PostMapping("/register")
  public AppUser register(@RequestBody RegisterForm userForm){
      if(!userForm.getPassword().equals(userForm.getRepassword()))
      throw new RuntimeException("You must confirm your password");
      AppUser user = accountService.findUserByUsername(userForm.getUsername());
      if(user!=null) throw new RuntimeException("this  use already exist");
      AppUser appUser =new AppUser();
      appUser.setUsername(userForm.getUsername());
      appUser.setPassword(userForm.getPassword());
      accountService.saveUser(appUser);
      accountService.addRoleToUser(userForm.getUsername(), "USER");
      return appUser;
    }


//Rafrechir le token de l'utilisateur    
@GetMapping(path="/refreshToken")
public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception{
String auhToken =request.getHeader("Authorization");
if(auhToken!=null && auhToken.startsWith("Bearer ")){
  try {
    String jwt = auhToken.substring(7);
    Algorithm algorithm =Algorithm.HMAC256("mySecret1234");
    JWTVerifier jwtVerifier =JWT.require(algorithm).build();
    DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
    String username =decodedJWT.getSubject();
    AppUser appUser =accountService.findUserByUsername(username);
    String jwtAccessToken =JWT.create().
    withSubject(appUser.getUsername())
    .withExpiresAt(new Date(System.currentTimeMillis()+5*60*100))
    .withIssuer(request.getRequestURL().toString())
    .withClaim("roles", appUser.getRoles().stream().map(
    r->r.getRoleName()).collect(Collectors.toList())).sign(algorithm);

    Map<String,String> idtoken =new HashMap<>();
    idtoken.put("access-token", jwtAccessToken);
    idtoken.put("refresh-token", jwt);
    response.setContentType("application/json");
    new ObjectMapper().writeValue(response.getOutputStream(), idtoken);
    


  } catch (Exception e) {
    throw e;
  }
}else{
  throw new RuntimeException("Refresh token required!!!");

}


}

@GetMapping(path="/profile")
public AppUser profile(Principal principal){
  return accountService.findUserByUsername(principal.getName());
  
}



}

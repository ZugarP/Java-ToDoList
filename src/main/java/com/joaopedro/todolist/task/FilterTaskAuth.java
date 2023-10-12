package com.joaopedro.todolist.task;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.joaopedro.todolist.user.IUserRepository;

import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter{

    @Autowired
    private IUserRepository userRepository;



    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {

              var servletPath = request.getServletPath();
              if(servletPath.startsWith("/tasks/")){

                  // Pegar autenticação usuario e senha  
                      // recebe o request
                  var authorization = request.getHeader("Authorization");
                  
                      // limpa o request para ficar somente a parte necessaria
                  var authEncoded = authorization.substring("Basic".length()).trim();

                  // converte em bytes
                  byte[] authDecoded = Base64.getDecoder().decode(authEncoded);
                      // converte o byte em string
                  var authString = new String(authDecoded); 
                      // Divide a string em usuario e senha 
                  String[] credentiasl = authString.split(":");
                  String username = credentiasl[0];
                  String password = credentiasl[1];


                  // validar usuario e senha

                  var user = this.userRepository.findByUsername(username);
                  if( user == null){
                      response.sendError(401);

                  }else{
                    var passwordVerify=   BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                    if(passwordVerify.verified){
                      request.setAttribute("idUser",user.getId());
                      filterChain.doFilter(request, response);
                    }else{
                      response.sendError(401);
                    }

                  }
              }else{

                filterChain.doFilter(request, response);
              
              }


    }
    

 
    
}

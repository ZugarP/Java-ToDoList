package com.joaopedro.todolist.user;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import at.favre.lib.crypto.bcrypt.BCrypt;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private IUserRepository userRepository;



    @PostMapping("/")
    public  ResponseEntity create(@RequestBody UserModel userModel){

        var user = this.userRepository.findByUsername(userModel.getUsername());

        if (user != null) {
            return ResponseEntity.status(400).body("usuario ja existe");
        }

            // criptografando senha

        var passowrdHashed = BCrypt.withDefaults().hashToString(12, userModel.getPassword().toCharArray());

        // definindo a senha criptografada
        userModel.setPassword(passowrdHashed);

        var userCreated =this.userRepository.save(userModel);
        return ResponseEntity.status(200).body(userCreated);


    }
    


}

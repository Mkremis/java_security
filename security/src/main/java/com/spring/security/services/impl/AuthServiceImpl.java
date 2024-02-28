package com.spring.security.services.impl;

import com.spring.security.persistence.entities.UserEntity;
import com.spring.security.persistence.repositories.UserRepository;
import com.spring.security.services.IJWTUtilityService;
import com.spring.security.services.models.dtos.LoginDTO;
import com.spring.security.services.models.dtos.ResponseDTO;
import com.spring.security.services.models.validation.UserValidation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Optional;

@Service
public class AuthServiceImpl implements IAuthService{
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private IJWTUtilityService jwtUtilityService;

    @Autowired
    private UserValidation userValidation;

    @Override
    public HashMap<String, String> login(LoginDTO login) throws Exception {
        try {
            HashMap<String, String> jwt = new HashMap<>();
            Optional<UserEntity> user = userRepository.findByEmail(login.getEmail());

            if(user.isEmpty()){
                jwt.put("error", "User not registered!");
                return jwt;
            }
            //verificar la contraseña

            if(verifyPassword(login.getPassword(), user.get().getPassword())){
                jwt.put("jwt", jwtUtilityService.generateJWT(user.get().getId()));
            }else {
                jwt.put("error", "Authentication failed!");
            }
            return jwt;
        }catch (Exception e){
            throw new Exception(e.toString());
        }
    }

    public ResponseDTO register(UserEntity user) throws Exception{
        try{
            ResponseDTO response = userValidation.validate(user);
            if(response.getNumOfErrors()>0){
                return response;
            }
            List<UserEntity> getAllUsers = userRepository.findAll();
            for(UserEntity repeatFields : getAllUsers){
                if(repeatFields!=null){
                    response.setNumOfErrors(1);
                    response.setMessage("User already exists!");
                    return response;
                }
            }
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
            user.setPassword(encoder.encode(user.getPassword()));
            userRepository.save(user);
            response.setMessage("User created successfully!");

            return response;

        }catch (Exception e){
            throw new Exception(e.toString());
        }

    }

    private boolean verifyPassword(String enteredPassword, String storedPassword){
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder.matches(enteredPassword, storedPassword);
    }
}

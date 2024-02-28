package com.spring.security.services.models.validation;

import com.spring.security.persistence.entities.UserEntity;
import com.spring.security.services.models.dtos.ResponseDTO;

public class UserValidation {

    public ResponseDTO validate(UserEntity user){
        ResponseDTO response = new ResponseDTO();
        response.setNumOfErrors(0);
        if(user.getFirstName()== null
                || user.getFirstName().length()<3
                || user.getFirstName().length()>15
        ){
            response.setNumOfErrors(response.getNumOfErrors()+1);
            response.setMessage("First name must be between 3 and 15 characters.");
        }
        if(user.getLastName()== null
                || user.getLastName().length()<3
                || user.getLastName().length()>30
        ){
            response.setNumOfErrors(response.getNumOfErrors()+1);
            response.setMessage("Last name must be between 3 and 30 characters.");
        }
        if(user.getEmail() == null
                || !user.getEmail().matches("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")) {
            response.setNumOfErrors(response.getNumOfErrors() + 1);
            response.setMessage("Invalid email format.");
        }
        if (user.getPassword() == null || !user.getPassword().matches("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$")) {
            response.setNumOfErrors(response.getNumOfErrors() + 1);
            response.setMessage("Password must be at least 8 characters long, contain at least one digit, one lowercase letter, one uppercase letter, one special character, and no whitespace.");
        }



        return response;
    }
}

package com.joaopedro.todolist.errors;

import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ExceptionHandlerController {
    
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<String> handleHttpMEssageNotREadableExcpetion(HttpMessageNotReadableException e){
        return ResponseEntity.status(400).body(e.getMostSpecificCause().getMessage());
    }
}

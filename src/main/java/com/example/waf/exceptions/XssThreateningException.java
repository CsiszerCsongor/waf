package com.example.waf.exceptions;

public class XssThreateningException extends Exception{

    private String message;

    public XssThreateningException(String message){
        super(message);
        this.message = message;
    }

    public XssThreateningException(String message, Throwable err){
        super(message, err);
        this.message = message;
    }

}

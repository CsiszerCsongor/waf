package com.example.waf.service;

import com.example.waf.exceptions.XssThreateningException;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;

public interface RequestXssChecker {
    void checkRequest(HttpServletRequest request, String body) throws XssThreateningException, IOException;
}

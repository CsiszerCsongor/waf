package com.example.waf.service.checker;

import com.example.waf.exceptions.XssThreateningException;

import javax.servlet.http.HttpServletRequest;

public interface XssChecker {
    void checkRequest(HttpServletRequest request) throws XssThreateningException;
}

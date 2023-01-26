package com.example.waf.service;

import com.example.waf.exceptions.XssThreateningException;
import com.example.waf.service.checker.DOMBasedXssChecker;
import com.example.waf.service.checker.ReflectedXssChecker;
import com.example.waf.service.checker.StoredXssChecker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Service
public class RequestXssCheckerImpl implements RequestXssChecker {

    private ReflectedXssChecker reflectedXssChecker;
    private StoredXssChecker storedXssChecker;
    private DOMBasedXssChecker domBasedXssChecker;

    @Autowired
    public RequestXssCheckerImpl(ReflectedXssChecker reflectedXssChecker,
                                 StoredXssChecker storedXssChecker,
                                 DOMBasedXssChecker domBasedXssChecker){
        this.reflectedXssChecker = reflectedXssChecker;
        this.storedXssChecker = storedXssChecker;
        this.domBasedXssChecker = domBasedXssChecker;
    }

    @Override
    public void checkRequest(HttpServletRequest request, String body) throws XssThreateningException, IOException {
        if ("GET".equalsIgnoreCase(request.getMethod())){
            reflectedXssChecker.checkRequest(request);
        }
        if ("POST".equalsIgnoreCase(request.getMethod())){
            storedXssChecker.checkRequest(request, body);
        }
        // TODO          checkHeadersAgainstXss(request);
        // TODO          checkCookiesAgainstXss();
        // TODO          checkBodyAgainstXss(request);

    }

}

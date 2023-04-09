package com.example.waf.service.checker;

import com.example.waf.exceptions.XssThreateningException;
import com.example.waf.service.XssRegexLoader;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Enumeration;

@Slf4j
@Service
public class ReflectedXssChecker extends XssCheckerBase {

    @Autowired
    public ReflectedXssChecker(
            final XssRegexLoader xssRegexLoader
    ) {
        super(xssRegexLoader);
    }

    @Override
    protected void throwException(String parameterName, String parameterValue) throws XssThreateningException {
        throw new XssThreateningException("GET : Malicious code detected in parameter : " + parameterName +
                                                  "\nParameter value : " + parameterValue);
    }

    @Override
    public void checkRequest(final HttpServletRequest request) throws XssThreateningException {
        Enumeration<String> parameterNames = request.getParameterNames();

        while (parameterNames.hasMoreElements()) {
            String parameterName = parameterNames.nextElement();
            if (textContainsMaliciousCode(request.getParameter(parameterName))) {
                throwException(parameterName, request.getParameter(parameterName));
            }
        }
    }

}

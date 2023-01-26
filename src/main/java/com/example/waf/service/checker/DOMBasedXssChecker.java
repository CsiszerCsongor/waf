package com.example.waf.service.checker;

import com.example.waf.exceptions.XssThreateningException;
import com.example.waf.service.XssRegexLoader;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

@Service
public class DOMBasedXssChecker extends XssCheckerBase {

    public DOMBasedXssChecker(
            final XssRegexLoader xssRegexLoader
    ) {
        super(xssRegexLoader);
    }

    @Override
    public void checkRequest(final HttpServletRequest request) throws XssThreateningException {

    }

    @Override
    protected void throwException(final String parameterName, final String parameterValue)
            throws XssThreateningException {
        throw new XssThreateningException(
                "GET : Malicious code detected in parameter : " + parameterName + "\nParameter value : " +
                        parameterValue);
    }

}

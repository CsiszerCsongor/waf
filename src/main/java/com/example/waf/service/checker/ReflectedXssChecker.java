package com.example.waf.service.checker;

import com.example.waf.exceptions.XssThreateningException;
import com.example.waf.service.DecoderService;
import com.example.waf.service.XssRegexLoader;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.regex.Pattern;

@Slf4j
@Service
public class ReflectedXssChecker {

    private XssChecker xssChecker;

    @Autowired
    public ReflectedXssChecker(XssChecker xssChecker){
        this.xssChecker = xssChecker;
    }

    public void checkParametersAgainstXss(HttpServletRequest request) throws XssThreateningException {
        Enumeration<String> parameterNames = request.getParameterNames();

        while (parameterNames.hasMoreElements()) {
            String parameterName = parameterNames.nextElement();
            if (xssChecker.textContainsMaliciousCode(request.getParameter(parameterName))) {
                throwException(parameterName, request.getParameter(parameterName));
            }
        }
    }

    private void throwException(String parameterName, String parameterValue) throws XssThreateningException {
        throw new XssThreateningException("GET : Malicious code detected in parameter : " + parameterName +
                                                  "\nParameter value : " + parameterValue);
    }

}

package com.example.waf.service.checker;

import com.example.waf.exceptions.XssThreateningException;
import com.example.waf.service.DecoderService;
import com.example.waf.service.XssRegexLoader;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;

@Slf4j
@Service
public class StoredXssChecker extends XssCheckerBase{

    @Autowired
    public StoredXssChecker(XssRegexLoader xssRegexLoader){
        super(xssRegexLoader);
    }

    // TODO what if text contain multiple & character?
    public void checkRequest(HttpServletRequest request, String body) throws XssThreateningException, IOException {
        body = DecoderService.decodeUntilIsNotDecoded(body);
        String[] bodyKeyValues = body.split("&");

        for (String keyValue : bodyKeyValues){
            String[] keyValueParts = keyValue.split("=");
            String key = keyValueParts[0];
            String value = keyValueParts[1];
            if (textContainsMaliciousCode(value)){
                throwException(key, value);
            }
        }
        log.info(body);
    }

    @Override
    protected void throwException(String parameterName, String parameterValue) throws XssThreateningException {
        throw new XssThreateningException("POST : Malicious code detected in parameter : " + parameterName +
                                                  "\nParameter value : " + parameterValue);
    }

    @Override
    public void checkRequest(final HttpServletRequest request) throws XssThreateningException {

    }

}

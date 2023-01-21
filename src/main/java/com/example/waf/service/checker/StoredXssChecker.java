package com.example.waf.service.checker;

import com.example.waf.exceptions.XssThreateningException;
import com.example.waf.service.DecoderService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.stream.Collectors;

@Slf4j
@Service
public class StoredXssChecker {

    private DecoderService decoderService;
    private XssChecker xssChecker;

    @Autowired
    public StoredXssChecker(DecoderService decoderService){
        this.decoderService = decoderService;
    }

    public void checkRequest(HttpServletRequest request, String body) throws XssThreateningException, IOException {
        body = decoderService.decodeUntilIsNotDecoded(body);
        String[] bodyKeyValues = body.split("&");

        for (String keyValue : bodyKeyValues){
            String[] keyValueParts = keyValue.split("=");
            String key = keyValueParts[0];
            String value = keyValueParts[1];
            if (xssChecker.textContainsMaliciousCode(value)){
                throwException(key, value);
            }
        }
        log.info(body);
    }

    private void throwException(String parameterName, String parameterValue) throws XssThreateningException {
        throw new XssThreateningException("POST : Malicious code detected in parameter : " + parameterName +
                                                  "\nParameter value : " + parameterValue);
    }

}

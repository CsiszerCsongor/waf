package com.example.waf.service.checker;

import com.example.waf.exceptions.XssThreateningException;
import com.example.waf.service.DecoderService;
import com.example.waf.service.XssRegexLoader;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Slf4j
@Component
public abstract class XssCheckerBase implements XssChecker {
    protected XssRegexLoader xssRegexLoader;

    public XssCheckerBase(XssRegexLoader xssRegexLoader){
        this.xssRegexLoader = xssRegexLoader;
    }

    public boolean textContainsMaliciousCode(String text) {
        text = DecoderService.decodeUntilIsNotDecoded(text);

        if (!xssRegexLoader.getWhitelistedHtmlTagsList().isEmpty()) {
            return isBlacklistedTagsAndAttributesAppearInText(text);
        }
        else {
            return checkForAnyHtmlTag(text);
        }
    }

    private boolean checkForAnyHtmlTag(String text) {
        for (Pattern anyHtmlTag : xssRegexLoader.getRegexAgainstAnyHtmlTagPatterns()) {
            if (anyHtmlTag.matcher(text).find()){
                return true;
            }
        }

        return false;
    }

    private boolean isBlacklistedTagsAndAttributesAppearInText(String text) {
        for (Pattern blackListedTag : xssRegexLoader.getBlacklistedHtmlTagsList()) {
            if (blackListedTag.matcher(text).find()){
                logRequestAndRegexWhichCaughtTheRequest(text, blackListedTag);
                return true;
            }
        }

        for (Pattern blacklistedTagAttribute : xssRegexLoader.getBlacklistedHtmlTagAttributesList()) {
            if (blacklistedTagAttribute.matcher(text).find()){
                logRequestAndRegexWhichCaughtTheRequest(text, blacklistedTagAttribute);
                return true;
            }
        }

        return false;
    }

    private void logRequestAndRegexWhichCaughtTheRequest(String text, Pattern regex) {
        log.info("Find XSS attack in request. Regex which caught it : " + regex.toString() + "\n" +
                         "Text : " + text);
    }

    protected abstract void throwException(String parameterName, String parameterValue) throws XssThreateningException;
}

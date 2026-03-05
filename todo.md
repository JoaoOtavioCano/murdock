# To-do:
[x] decide id type
[x] how to generate salts
[x] password requirements (size, characters needed)
[x] is there any difference in the database that should be implemented for security?
[x] create a Authenticator type responsible for the authentication separated from the server. This would allow different APIs(REST, websocket, gRPC)
[x] implement hexagonal architecture
[x] increase time that the sign in takes every try needed
[] CRUD users (missing DELETE, UPDATE, READ)
[] embed 10k worst passwords file
[] hash map of most common passwords?
[] better error handling (better messages)
[] docker setup
[] email confirmation
[] recover password
[] blocklist should contain strings of at least 8 characters
[] how to generate pepper
[] evaluate salt and encrypted password hex encoding length
[] should an index be created for the email?
[] cache implementation?
[] create a event based error handling.Ex: in signup, send email fails and delete user from database fails
[] in the createUser for EmailPasswordMethod if duplicated key validate if user is pending. if so create a new confirm code

# passwords composition
[NIST Document](https://pages.nist.gov/800-63-4/sp800-63b.html#appA)
## length
* Users should be encouraged to make their passwords as long as they want within reason.
* passwords as single factor authentication must require at leas 15 characters ([link](https://pages.nist.gov/800-63-4/sp800-63b.html#password))
* passwords as part of a multi-factor authentication must require at leas 8 characters ([link](https://pages.nist.gov/800-63-4/sp800-63b.html#password))
* max length may be at least 64 characters. ([link](https://pages.nist.gov/800-63-4/sp800-63b.html#password))
* maybe encourage the user to use a password at least 16 characters long [paper referenced by the NIST document.](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=6234434)
## composition
* allowing spaces is good so the user can use a passphrase.
* users tend to be 


# blocklist
* https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader it came from this owasp [link](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#implement-proper-password-strength-controls)
# Rate limiting
* https://pages.nist.gov/800-63-4/sp800-63b.html#throttle
* https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#login-throttling
* Amount of time to delay after each account lockout (max 2-3, after that permanent account lockout). [owasp](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#login-throttling)
* The number of failed attempts before the account is locked out (lockout threshold).
* The time period that these attempts must occur within (observation window).
* How long the account is locked out for (lockout duration)

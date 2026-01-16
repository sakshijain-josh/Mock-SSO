Build a mock SSO flow with authorization-code exchange
Write a program that:

Simulates redirect step


Print: "Redirecting to Identity Provider..."


Simulates IdP Login


User enters username + password


Program pretends login is valid


Program prints: "EX: Auth Code: XYZ123"


Simulates Token Exchange


User enters the auth code


Program returns a mock ID token + access token, e.g.

{ id_token: "abc.id.sig", access_token: "xyz.access.sig" }

 
Simulates Token Verification

Program verifies:


Token is not empty


Token has valid structure


Token contains expected claims


Print "Token Verified" or "Invalid Token"
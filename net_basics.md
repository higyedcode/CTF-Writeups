
>Basics of Networking

When connecting to a TCP server, a 3 way handshake is performed

**client first
[SYN, SYN-ACK, ACK]

when sending a message you have an additional data layer
Layers:
Ethernet(mac addresses)
IP layer(IP addresses )
TCP( ports )
Data

same way when exiting
**client first
[FIN, ACK],[ACK, FIN],[ ACK ].

>VULNERABLITIES OF RANDOM

- analyse the seed of the random function:
srandom(time(NULL));
this uses the current time, so if you're fast enough you can see that you can get entries that are the same, even though it seems "random"

>gdb application

You can attach a corefile when calling gdb to examine the situation when from the moment the program crashed. 
Ex: if you have a server, that creates a fork or dup for every client, then the exploit happens in a child process, that crashes, but no error is visible in the main program. You then look for the core dump, and attach that in gdb, OR you debug the code with gdb but attach the flag :

(gdb) set follow-fork-mode child

>0x1d done.

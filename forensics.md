# Volatility3 guide for plugins

- linux.pslist - processes running, PID and PPIDs
- linux.pstree - displays the parent child relationships between processes
- linux.bash   - the commands that were run in bash


---------------------------------------------------------------------
### LIST PLUGINS - pretty fast, but vulnerable. If attacked by malware, could potentially hide some processes that would not show up in the _EPROCESS linked list (Task manager)

### SCAN PLUGINS - approach similar to carving the memory for things that might be hidden -> can yield also false positives

- banners.Banners - dusplays all the options required to build the component 

- windows.info.Info - displays OS information

- windows.hashdump.Hashdump - #Grab common windows hashes (SAM+SYSTEM)
	- SAM(Security Accound Manager): user account info, hashed passwords
	- SYSTEM information about Windows system
	
- windows.cachedump.Cachedump - #Grab domain cache hashes inside the registry
	- Cached domain credentials are stored in the registry to facilitate 		offline authentication in case the domain controller is unavailable
	
- windows.lsadump.Lsadump - #Grab lsa secrets
	- LSA(local Security Authority) secrets
	- passwds+keys+credentials used for system operations and services.
	- ex: cached domain credentials, service account passwords + autologon passwords


- windows.pstree.PsTree - loook for suspicious/unexpected child processes (ex: a cmd.exe as a child of iexplorer.exe)
- windows.pslist.PsList - get process list (EPROCESS)
- windows.psscan.PsScan - get hidden processes 

- windows.dumpfiles.DumpFiles --pid <pid> - Dump the .exe and dlls of the process in the current directory

- windows.cmdline - commands executed in cmd.exe are managed by conhost.exe or csrss.exe on systems before Windows7.

- windows.envars - get env variables

- windows.handles - checks which files/keys/threads/processes a process has OPENED.
 - windows.dlllist

### ALLOWS TO FIND PROCESS TO WHICH STRING BELONGS TO ###

`strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt`
#

- windows.registry.userassist.UserAssist - keeps track of programs you run and how many times it was executed, and WHEN IT WAS LAST RUN.


---------------------------------------------------------------------------------
## Windows Security Process

- User registers -> username + password (hashed) stored in the `SAM database`

- The hashing algorithm used by Windows is `NTLM` (NT LAN Manager), and it uses the `pass + a random salt` (to prevent dictionary/rainbow attacks).

`SAM database : Windows\System32\config , accountInfo + SIDs + GroupMembership + Password Hashes`

**The cached keys are found at**: `HKEY_LOCAL_MACHINE\Security\Cache key`

	BY DEFAULT, WINDOWS CACHES THE CREDENTIALS OF THE LAST 10 USERS WHO HAVE LOGGED ON!!

`LSA secrets can be found: HKEY_LOCAL_MACHINE\Security\Policy\Secrets`

- The cached credentials have a time limit, LSA secrets persist until explicitly changed.

---------------------------------------------------------------------------------








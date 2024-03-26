# PWN NOTES 

# ret2libc
 - you have to **leak the address** of some function, than always `FIND YOUR WAY BACK TO THE BASE OF LIBC`

- Compute the `offset` from that specific version of libc,substract the offset of the leaked function, and add the offset of what you want.

#

### Assembly Basics -> Function calls:
- in 32 bit, the function takes the arguments `OFF THE STACK`
- in 64 bit, the function takes the arguments from the `REGISTER(RDI,RSI,RDX in this order)`


#

### You can upload your local libc library, and then just do this in python pwn script:
	
	libc = elf('path_to_libc')
	libc.address = base_address which you need to find/leak
	libc.symbols.system - to get system
	next(libc.search(b'/bin/sh\x00')) -- to get /bin/sh string

`one_gadget` run against libc library might find reverse shell instructions conditioning that some registers have certain values.

        vickie li - good writeups and stuff
        ASLR/PIE - Nightmare blog

        ASLR is OS-level, applies to stack addresses generally.
        PIE is the same concept but for the binary addresses.
#

### The Global Offset Table 

- The `GOT` is populated with the functions from libc, specifically with the `offsets of these functions in your local libc library!!!` So that the next time it sees printf, it can just go to that offset in your LOCAL libc library.( **THAT IS WHY IT IS DINAMICALLY LINKED** )

        !!! ALL LIBC LIBRARIES ARE DIFFERENT, some have multiple lines of code, DIFFERENT ADDRESSES!!!

#
        You need to know the LIBC version on the remote server to use that also on your local machine to call vulnerable function's and find out their OFFSETS on the SERVER!


### GDB_PWNDBG instruction
        breakrva 0x11f0, breaks at the offset givven from the base of the PIE base address

#

## Bypass PIE restrictions -- leak PIE
You need to get `back to the BASE OF THE BINARY`

`2 steps involved`:
- do it locally, in gdb, when setting up the script add piebase, to leak the base of the binary in the local environment
- then still locally, leak addresses from the stack that point to somewhere in the program(like <main+44>) and then substract the piebase address to find the offset of the n-th element from the stack.
- Then using this offset, leak the n-th element on the remote server, remove the offset -> you got the base of the binary.

`THEN UPDATE THE [elf.address] VALUE`, to be able to call:
elf.got.puts, elf.symbols.vuln, ...

#

### WHEN LEAKING GOT:
- Let's say you leak the pust address, than take that address and paste it in this `"libc database search"` website, that tells you what possible libc libraries are running on the `REMOTE SERVER`!!!

#

### FULL RELRO protection 
- means that `GOT and some stack addresses` are `READ-ONLY` and cannot be overriden
### PARTIAL RELRO 
- we can overwrite `GOT`

#

### STACK CANARIES -- detecting stack smashing

- In ghidra, you can see underneath function definitions in the left pane how the stack looks for the function call:
ex -- local_8, canary, buffer.

### CANARY TIPS 
- find the aproximate location of the canary, in relation with the input that you control(ex it is 64 bytes from the buffer). 
- `To identify it: looks very random, ends in 00, usually.`

- Other identifying tips: `libc addresses tipically start with ff, f7.`

- #### Locally, in gdb you have the `canary` command, that `leaks that value for you at that time`, then do [x/100x $esp] to llist 100 hex values from the stack, and see at which position the canary is found, and then even on a remote server the canary will be at that position on the stack.

#

## INJECTING SHELLCODE

- use libraries:
- `shellcraft` ex: **shellcode = asm(shellcraft.cat('flag.txt'))**

- use `asm('nop')` instead of 'A' to not be executed!!! - for padding inside payload

- `BAD CHARACTERS(\x00 or \n)` can cause errors! SOmehow encode it if that is the case.

- `msfvenom` : you can encrypt payload, remove BAD characters!, list a lot of payloads

### FOR SHELLCODE 
- we are gonna be using `jmp esp` to jump to the executable code on the stack. You have to make sure that that `code fits`. If the msfvenom doesn't fit, you can put some of it before the jmp esp(maybe the padding to the buffer overflow is larger than the space after it for the executable code), then substract from esp a certain value, then [jmp esp] to the new stack head.

#

### Interesting fact: once you have a shell, you can do this to make it fully interactive:

        python -c 'import ptyl pty.spawn("/bin/bash");'
        CTRL + Z
        stty raw -echo; fg;
        export TERM=xterm

#

> check out -- bat computer at crypto cat

#

        You can use r = ROP(elf), then use :
        r.rdi.address -- for pop rdi gadget
        r.got['printf'], or r.plt['puts'],r.sym['main']

#

- `To determine base address of libc - ldd executable`
- To get system from libc - `readelf -s -t x path_to_libc_found_in_ldd | grep system`
- To get got fgets : `objdump -R /path/to/your/executable`
- To find base of binary: in pwn, e = ELF(), e.address.

#

## Debugging shellcode for stack shellcode injections!

- I have a payload, that I got from shellstorm, but I cannot get it to spawn the shell. Doing some investigation, I found that you can `single step through instructions with 's' in pwndbg`, and that you can examine `even the bites or instructions that are your shellcode`, to make sure that the result is `identical with the shellcode you expect` to appear on the stack. (for this i used commands like: `x/10i adr, x/40b addre`)

- The code seems to be fine, but the shell is not working. Then I analysed, and the correct arguments were passed in the correct registers: rdi, rsi, rdx, in this order, I had in rax 59, BUT THE RETURN VALUE of syscall, which is stored in rax is 0xfffffffffffffff2. In the documentation, I found that the errorcode returned is actually "-errno", so this error code is actaully 0xd = 14. => EFAULT, bad address.

- `I FINALLY FIGURED IT OUT!!! `
- It was `bad address` because, in order to do the syscall you have to have `ALSO ON THE STACK THE ARGUMENTS` for the Linux kernel implementation of the syscall, meaning what registers or stack values the actual function is working with are modifying!!!

- `SO, ON THE STACK, WHEN DOING THE SYSCALL to EXECVE, YOU NEED LIKE THIS `:
- Put the values path, argv, env in rdi, rsi, rdx;  in our case: bin/bash, bin/bash,0
-  Put the values path, env, argv also on the stack!!! In THAT ORDER, meaning: 

        $rsp   : /bin/bash - or address of /bin/bash
        $rsp+8 : 0
        $rsp+16: /bin/bash (in hex)

### THE QUICKEST FIX: 
        shellcode = b'\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05'
        
        OR

        shellcode = asm('xor eax,eax') + shellcode

To write more asm code, use inline asm syntax: (xor eax,eax; xor ebx,ebx; xor ecx,ecx;)

#

To create your own shellcode do this: 

# Create a asm file, with the following boilerplate:
        section .text
                global _start
        
        _start:
                xor     rax, rax
                xor     rdx, rdx
                mov     qword rbx, '//bin/sh'
                shr     rbx, 0x8
                push    rbx
                mov     rdi, rsp
                push    rax
                push    rdi
                mov     rsi, rsp
                mov     al, 0x3b
                syscall
#

Then compile it like this:

`nasm -f elf64 -o myfile.o myfile.asm `

`ld -s -o myfile_exectuable myfile.o (linker)`

`./myfile_executable`

#

To see the compiled hex code to add to your exploits: 

> xxd -p myfile.o > myfile.hex

or

> xxd myfile.o > myfile.hex, and look for the code with bin/sh.

# 

#### Other stuff I observed:
- to put /bin/bash you remain with a null byte that's why you need the shr.
If you write mov rax, 0 it will be ignored by the asm if it's the first instruction. That's why we need the xor rax, rax.

#

#### THE NEED TO REMOVE NULL BYTES:

`\x00` is the most common null byte that should not be found in our exploits, due to the fact that most challenges use `strcpy,strcat,scanf,sprintf`, which will perform string operations `UNTIL THEY ENCOUNTER A NULL BYTE`, so our payload could be prematurely stopped and not all of the shellcode executed.


#### Some targets might filter out certain "bad bytes", like 0x00-0x20 maybe

#

#### Some things to be careful about when doing shellcodes:

`LOOKOUT FOR push instructions` in your shellcode not to override the actual shellcode with the values poped on the stack. ex: You generally have only as long as your buffer for the shellcode, but if you want to be sure you have space do this: 
add padding + jmp + looong nop slide, then the shellcode.

`JUST MAKE SURE YOUR SHELLCODE DOESN't AUTODISTRUCT. Look out for push instructions.`

#
Pwn challnges on Youtube

Pwny Racing - youtube
#

### HEAP overflow.

- WHEN allocating heap memory with malloc, what happens behind the scenes is that `8 bytes get allocated` before as the `head of that heap segment`, along with the actual data with whatever size it is. In the HEAD of the heap segment, it is indicated the `nr of bytes of the heap segment`, along with `1 indicating that that heap is occupied(important when freeing the memory)`. So if we allocate 8 bytes for a string let's say, the header will be 00000000 00000011.

- After the allocated heap, the free heap is then considered as another `BIG HEAP` segment, so a `HEAP header` is associated indicating the size of the free heap.

### gdb instructions: 
 - [ backtrace ],
 - [ disassemble address ] - will disassemble the whole function to which that address belongs to.
 - to find the got address of a libc function do this:

        take the call instruction: call 0x80483cc <puts@plt>
        disassemble 0x80483cc
        find the jmp in the disassembled function
        the jmp address is the GOT of the libc function
        Check with x addrr: you should see something like: <_GLOBAL_OFFSET_TABLE_+36>

- info registers
- info proc mappings - we can see the heap, stack, all memory areas
- define hook-stop
- x/64wx heap_address
- end

makes it display the heap by default at every breakpoint

- set $i1 = (struct internet*) addr
- print *$i1

#

### Reversing Statically linked binaries with function signatures

- to compile a stripped binary: add -s; to make it static use: -static
gcc a.c -s -static -o a


- `TO FIND MAIN`: 
- go to the `entry` function, find the `__libc_start_main`(FUN_0019228192,...
- 		MAIN is gonna be FUN_00192838182.

- To identify libc functions in stripped static binary you should always find the SYSCALL it executes, and then you'll know the function most likely.
- analyse the function arguments and the nr of arguments

### OR

 - You can use IDA FLIRT signatures, which uses function signmatures to identify the libc functions.
how to set it up: 
https://www.youtube.com/watch?v=CgGha_zLqlo&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=20


# 

### HEAP use-after-free exploits

- This vulnerabilty exploits the fact that if a pointer [p] is pointing to a memory address [a], but then we use free(p) to free the memory, then p STILL POINTS to that address. If you the use malloc or any function like dup that allocates new heap memory, the new heap memory will be where the p freed memory is. so then if you modify the value of the newly allocated memory [pp], then you modify the value stored also in [p], thus using `THE MEMORY AFTER FREE`.


 - setting up your own display panel, with your own stuff in gdb: when hitting breakpoints
(gdb) command
Type commands for breakpoint(s) 1, one per line.
End with a line saying just "end".
>echo ----------------------------------------------------------------------------------\n
>x/20wx 0x804d9b8
>echo --auth----------------------------------------------------------------------------\n
>print *auth
>echo --service-------------------------------------------------------------------------\n
>print service
>echo ----------------------------------------------------------------------------------\n
>continue
>end

#


#### HEAP Once upon a free()

-  if you're in doubt/need to refresh knowledge:
https://www.youtube.com/watch?v=HWhzH--89UQ&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&index=31.

- this uses dlmaloc, shows how heap meta data can be modified to change program execution.

- when free() frees up the memory, it sets the first address(32 bits- 4 bytes) to 0, and then the metadata is either unchanged for the last free block before the WILDERNESS, either the metadata is set to point to the next free chunk in the heap(like a singly linked list).

- This is done for FASTBINS is set(little detail in the documentation of the free function from 2001). FASTBINS is enabled if the chunk size is larger than MAX_FAST_SIZE, which is usually 80.
FASTBINS is an array of lists holding recently freed small chunks.

- There are 2 types of chuncks(ex in 32 bits):
OCCUPIED chunks -- these have a 2*4bytes addresses(8 bytes) that represent the actual size and if it is occupied or not(indicated by the last bit being set). And after these 8 bytes there we have the allocated space with the data that is stored in that space.

- FREE CHUNKS -- these have 8 bytes header, just like occupied chuncks. IN THE FREED AREA, meaning the next 8 bytes, we have 2 32 bit addresses, where the first one is the forward pointer, and the second one is the backwards pointer.(pointing to prev/next free blocks).

______________________________________________________________

| prev_size | size    | fd-for freed chunks| bk-same|........|
_______________________________________________________________

first bit: previous in use bit!

ex:
__________________________________________________

| prev_size | 0x64    | fd       | bk   |........|
_________________________________________________
__________________________________________________

| prev_size | 0x65    | fd       | bk   |........|
_________________________________________________


### How the free works:
- It uses these fastbin lists, and consolidates the chunk we want to free with the other(1 or more) recently freed chunks. Let's assume it consolidates/merges only the last recently freed chunk with the the chunk we want to free. To do this, it UNLINKS the recently freed chunk from the fastbin list.HOW?

        %C code for it
        unlink(P,BK,FD){
        FD = P->fd;
        BK = P->bk;
        FD->bk = BK;
        BK->fd = FD;
        }

Like in any doubly linked list
	
        a[prev,nextb],b[preva,nextc],c[prevb,nextd].

        =>	a[prev, nextc],c[preva,nextd]

- Sets the next of the prev to be the next of current.
- Sets the prev of the next to be the prev of current.
- !!! But A is determined as C->PREV. So if we put a value CORRUPTED into C->PREV, then we go to CORRUPTED->NEXT = CORR_OVERWRITE.

- This way we can overwrite whatever we want with whatever we want.
**The corrupted->next is just *(corrupted + 12)

- The issue with such exploits is that you have to overwrite chuncks with values that include null bytes...which would be considered the end of the STRING!!!

### HOW DO WE BYPASS THAT?

- When calculating the next addresses, it just adds addr+nextsize for example.
- You can make nextsize ffff fffe ( = -2), so that when adding it just subtracts 2. (This happens because the addition would overflow the 32bit address space, so the 1 bit overflow is lost.



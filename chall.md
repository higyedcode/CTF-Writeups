The code is on %9$p position, but is only the first half byte.

### Unzip password protected zip file:

	zip2john file.zip > zip.hash
	john zip.hash

#
	binwalk 22.pdf and we see that there is a hidden zip file inside
	we do 'unzip 22.pdf' and we get an apk file
	apktools file.apk

Then search

Really `valuable resource` in `apk` files: `res/values/strings.xml`
Find one of the flags:
but the second one is encoded using affine with slope 19 and constant 1.


In setganography challenges, if you recognise a pattern, in a jpg when doing xxd over it, then maybe you have to remove all the words in that sentence. In this example, we had the brown fox jumps over the dog or something like this, once you remove them:
	sed 's/dog|jumps|.../g' file > outfile
Then the image becomes clear and you can see an image with the Unbreakable logo and a flag that is kinda erased.

	Next, a great tool for this is zsteg, which does lsb, and other techniques.


For the reverse engineering challenge: 
It takes the userFlag:
	if i is odd -> b[i] = u[i]+4
	if i is even -> b[i] = u[i]-4
	b[17]=(sumUsername/30)^buffer[j]
	
	
buf = flag -> flag

flag = 0x647c6f6c697c516c
667e7d6a77657c506c517c696c6f7c6444

_________________________________________________________________________

Important!!!
BINARY EXPLOITATION

The GOT has WRITE ACCESS always. The GOT is always fixed. We use that to leak the PLT address of some function to determine the libc library.

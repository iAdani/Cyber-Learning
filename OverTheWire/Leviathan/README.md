# Leviathan Wargame

This repository documents my progress through the Leviathan wargame from OverTheWire. Leviathan is focused on Linux privilege escalation and basic binary exploitation concepts. It builds on foundational command-line knowledge and introduces challenges involving SUID binaries, input manipulation, and simple logic flaws.

Each level involves escalating access from one user to another, simulating real-world scenarios often seen in penetration tests. I’ll be detailing how I solved each level, the commands and tools I used, and the key concepts I learned. Some levels were completed with the help of community hints or public write-ups, but I made sure to try by myself, understand and explain each solution in my own words.

## Level 0 → 1
```bash
ls -la
cd .backup
ls -la
cat bookmarks.html
grep bookmarks.html 'pass'
```
As we log in, we notice a hidden directory called `.backup`. Inside, there is a file `bookmarks.html`, which includes notes as an `HTML` format. We check if the next password is there using `grep`, and it actually is.

Password: `3QJ3TgzHDq`

## Level 1 → 2
```bash
ls -la
./check
cat check
```
There is a binary file called `check` in the home directory. When being executed, it asks for a password, and it is not the same password as `Leviathan1`. By printing `check` we can see it starts with `ELF`, which is a common format for binary executables. 

### ELF Files
`ELF` is a common file format for executables, object code, shared libraries, and core dumps in Unix-based systems. `ELF` files have a structure that contains the following sections, we will discuss some of them in more depth later on.
* `ELF Header` - each `ELF` file starts with a header that contains data about the file. 
* `Program Header Table` - This section tells the system how to create the process image.
* `.text` - contains the program's executable instructions.
* `.rodata` - contains read only data.
* `.data` - stores initialized global and static variables, data that can be read or write.
* `Section Header Table` - allows to locate all of the file sections, such as `.text` and `.data`. 
There might be more sections, such as `.comment`, which is for comments, and `.debug` for debugging information. 

The `readelf` command is a useful tool that allows to view detailed information about ELF files.
for example, if we use `readelf -h`, we can see a human-readable details from the `ELF Header`.

```bash
readelf -S check
readelf -x .rodata check
readelf -x .data check
strings check
```
The `readelf -S` command shows us the sections of an `ELF` file. We see there some interesting sections that might show the password. Using `readelf -x` we can see the `hex dump` of a specific section, this time we tried `.data` and `.rodata`, that might include the password, but it wasn't there. The `strings` command parses and shows all the strings in a binary file, but looking at the strings, nothing seems like the password.

```bash
ltrace check
```
the `ltrace` command shows what libraries are called during a program execution. So after using `ltrace` on our executable, it asks for the password. When given the wrong one, we can see very useful info:
```bash
__libc_start_main(0x80490ed, 1, 0xffffd494, 0 <unfinished ...>
printf("password: ")                                              = 10
getchar(0, 0, 0x786573, 0x646f67password: 123
)                                 = 49
getchar(0, 49, 0x786573, 0x646f67)                                = 50
getchar(0, 0x3231, 0x786573, 0x646f67)                            = 51
strcmp("123", "sex")                                              = -1
puts("Wrong password, Good Bye ..."Wrong password, Good Bye ...
)                              = 29
+++ exited (status 0) +++
```
The line we are interested in is `strcmp("123", "sex")`. We tried the password `123`, and the program called `strcmp`, which is a function to compare strings, on `123` and `sex`. What probably happened here, is that the program compared the input to the actually password, which is `sex`.

```bash
./check
sex
```
This is the right password. By cracking the password of this executable, it opens a shell that is being executed with `Leviathan2` permissions.
```bash
$ whoami
leviathan2
$ cat /etc/leviathan\_pass/leviathan2
NsN1HwFoyN
```
By using `Leviathan2` permissions, we can access it's password in `/etc/leviathan_pass/`.

Password: `NsN1HwFoyN`

## Level 2 → 3
```bash
ls -la
./printfile
./printfile /etc/leviathan_pass/leviathan3
./printfile /etc/leviathan_pass/leviathan2
```
We log in and notice the file `printfile`. When executed, it prints:
```bash
*** File Printer ***
Usage: ./printfile filename
```
When trying to print the password of `Leviathan3` it says:
```bash
You cant have that file...
```
But when we try to print the password for `Leviathan2` it gives a `Permission denied` error, which means that it probably has permissions to print the poassword of `Leviathan3`, so it must have the user's permissions.
```bash
ltrace ./printfile /etc/leviathan_pass/leviathan3
ltrace ./printfile .bash_logout
```
As we trace the function calls, the first one, that contains the password, only uses `access` command which checks if it has permissions to the given file. On the second try, with a file that actually getting printed we get:
```bash
__libc_start_main(0x80490ed, 2, 0xffffd474, 0 <unfinished ...>
access(".bash_logout", 4)                                         = 0
snprintf("/bin/cat .bash_logout", 511, "/bin/cat %s", ".bash_logout") = 21
geteuid()                                                         = 12002
geteuid()                                                         = 12002
setreuid(12002, 12002)                                            = 0
system("/bin/cat .bash_logout"# ~/.bash_logout: executed by bash(1) when login shell exits.

# when leaving the console clear the screen to increase privacy

if [ "$SHLVL" = 1 ]; then
    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
fi
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                            = 0
+++ exited (status 0) +++
```
We can see that `/bin/cat` is being used, which can be useful.

```bash
mktemp -d
touch /tmp/tmp.pb8pbUsODK/file\ with\ spaces
ltrace ./printfile /tmp/tmp.pb8pbUsODK/file\ with\ spaces
```
We create a file with spaces in its name, and try to use `printfile` to print it. We trace the execution and get this:
```bash
__libc_start_main(0x80490ed, 2, 0xffffd454, 0 <unfinished ...>
access("/tmp/tmp.pb8pbUsODK/file with sp"..., 4)                  = 0
snprintf("/bin/cat /tmp/tmp.pb8pbUsODK/fil"..., 511, "/bin/cat %s", "/tmp/tmp.pb8pbUsODK/file with sp"...) = 45
geteuid()                                                         = 12002
geteuid()                                                         = 12002
setreuid(12002, 12002)                                            = 0
system("/bin/cat /tmp/tmp.pb8pbUsODK/fil".../bin/cat: /tmp/tmp.pb8pbUsODK/file: No such file or directory
/bin/cat: with: No such file or directory
/bin/cat: spaces: No such file or directory
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                            = 256
+++ exited (status 0) +++
```
We can see that `access` tests `file with spaces`, but `cat` was called for every word separately. So it bypasses `access` and then it tries to print `/tmp/tmp.pb8pbUsODK/file`.

### Symbolic Links
A `symbolic link`, or a `soft link`, is a type of file that points to another file or directory. It is mainly used as a shortcut for files and directories, as it allows to access a file or directory from a different location without creating a copy of it. There is also another type of links, they're called `hard links` and they make files with the same `inode`, which is like having different names for the same file.

The `ln` command is a tool for creating links between files. By default it makes hard links, by adding the `-s` flag it can also make soft links.

```bash
ln -s /etc/leviathan_pass/leviathan3 /tmp/tmp.pb8pbUsODK/file
chmod 777 /tmp/tmp.pb8pbUsODK
./printfile /tmp/tmp.pb8pbUsODK/file\ with\ spaces
```
We made a soft link to the file with the password of `Leviathan3` and called it `/tmp/tmp.pb8pbUsODK/file`. As we seen before, `access` tests the permission of the original file in the input `/tmp/tmp.pb8pbUsODK/file with spaces`, but `cat` is executed on every word separately, so it runs `cat /tmp/tmp.pb8pbUsODK/file`, and because it links to the password file, the password is being printed.

Password: `f0n8h2iWLP`

## Level 3 → 4
```bash
ls -la
./level3
test
```
As we log in, there is one file called `level3`. When executed, it asks for a password. We test a password `'test'` and it prints `bzzzzzzzzap. WRONG`.
```bash
ltrace ./level3
test
```
We use `ltrace` to see what system functions are called and see this:
```bash
__libc_start_main(0x80490ed, 1, 0xffffd494, 0 <unfinished ...>
strcmp("h0no33", "kakaka")                                        = -1
printf("Enter the password> ")                                    = 20
fgets(Enter the password> test
"test\n", 256, 0xf7fae5c0)                                  = 0xffffd26c
strcmp("test\n", "snlprintf\n")                                   = 1
puts("bzzzzzzzzap. WRONG"bzzzzzzzzap. WRONG
)                                        = 19
+++ exited (status 0) +++
```
We can see the function `strcmp` that compares strings, and it compares out input with `'snlprintf'`.

```bash
./level3
Enter the password> snlprintf
[You've got shell]!
$ whoami
leviathan4
$ cat /etc/leviathan\_pass/leviathan4
WG1egElCvO
```
We found the password, and it gives us a shell with `Leviathan4` permissions. So we print it's password from the passwords file.

Password: `WG1egElCvO`

## Level 4 → 5
```bash
ls -la
cd .trash
ls -la
./bin
```
We log in, and there is a hiiden directory `.trash`. Inside there is only one file called `bin`, and as we execute it, it prints:
```bash
00110000 01100100 01111001 01111000 01010100 00110111 01000110 00110100 01010001 01000100 00001010
```
It looks like a binary presentation of the password, we need to convert it to `ASCII` characters.
```bash
mktemp -d
./bin > /tmp/tmp.AlzfJBVPVz/binary
for char in $(cat /tmp/tmp.AlzfJBVPVz/binary); do
> printf "\\x$(printf '%x' $((2#$char)))"
> done
```
First, we make a temp directory and copy `bin` output into a file called `binary`. Now we go through every char binary code from the file and print the `ASCII` presentation of it with `printf "\\x$(printf '%x' $((2#$char)))"`, let's explain:
* `$((2#$char))` - This part converts the char from binary to decimal (base 2 → base 10)
* `'%x'` - This part converts the decimal value to hex (base 10 → base 16)
* `\\x$(printf <previous bullets>)` - This part prints the hex value as a string, and adds `'\x'` in the beggining.
* Lastly, `printf` talkes the string we created that looks like this `'\x<hex value>'` and prints it as `ASCII`.

We do that for every char, and get the next password.

Password: `0dyxT7F4QD`

## Level 5 → 6
```bash
ls -la
./leviathan5
ltrace ./leviathan5
```
As we log in, there is a file `leviathan5`. When executed, it outputs an error: `cat: /tmp/file.log: No such file or directory`. It means that this executable tries to print the file `/tmp/file.log`, but it doesn't exists. We trace the running of `leviathan5` and get:
```bash
__libc_start_main(0x804910d, 1, 0xffffd494, 0 <unfinished ...>
fopen("/tmp/file.log", "r")                                       = 0
puts("Cannot find /tmp/file.log"Cannot find /tmp/file.log
)                                 = 26
exit(-1 <no return ...>
+++ exited (status 255) +++
```
We can see that `fopen` is called, so the program is trying to open this file, and the flag `"r"` means it is trying to read from that file. We understand that the `leviathan5` is trying to open a file called `file.log` in `/tmp`, read it, and then print it with `cat`.

```bash
ln -s /etc/leviathan\_pass/leviathan6 /tmp/file.log
./leviathan5
```
As we seen in level 2, we can create a `soft link` between files. So, we create the `/tmp/file.log`, and it is a soft link to the next level password. When `leviathan5` is executed, it uses `fopen` and `cat` on `file.log`, but because it is a soft link of the password file, the password is printed.

Password: `szo7HDB88w`

## Level 6 → 7
```bash
ls -la
./leviathan6
./leviathan6 0000
```
This time, there is a file called `leviathan6`, and when executed it prints:
```bash
usage: ./leviathan6 <4 digit code>
```
The program expects a 4 digit code. We try it with the code `0000` and it outputs `Wrong`. We can try to use the `Brute Force` approach in order to find the code, since it is only 4 digits.

```bash
for i in {0000..9999}; do
> ./leviathan6 $i
> done
```
After many attempts, we get access to a shell.

```bash
$ whoami
leviathan7
$ cat /etc/leviathan\_pass/leviathan7
qEs5Io5yM8
```
We got access to the shell as `Leviathan7`, so we print the password.

Password: `qEs5Io5yM8`

## Level 7
This is the last level. As we log in, there is a file that tells us 'Well done'.
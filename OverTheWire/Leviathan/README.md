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

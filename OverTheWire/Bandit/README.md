# Bandit Wargame

This repository tracks my progress through the Bandit wargame from OverTheWire. Bandit is designed for absolute beginners to learn the basics of using the command line and navigating Linux systems through a series of hands-on levels. Each level presents a small challenge that builds foundational cybersecurity and Linux skills.

I'll be documenting how I complete each level, commands I used, and what I learned along the way.

## Level 0 → 1
```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
cat readme
```
The `ssh` command stays the same for every level, except for changing the username, for example swap `bandit0` with `bandit1` for level 1.

Password: `ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If`

## Level 1 → 2
```bash
cat ./\-
```
Trying to open a file starting with a symbol requires using a backslash.

Password: `263JGJPfgU6LtdEvgfWU1XP5yac29mFx`

## Level 2 → 3
```bash
cat ./spaces\ in\ this\ filename
```

Password: `MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx`

## Level 3 → 4
```bash
cd inhere/
ls -l -a
cat ./...Hiding-From-You
```
Using `-a` flag for `ls` shows all files, including hidden files.

Password: `2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ`

## Level 4 → 5
```bash
cd inhere/
ls -l
cat ./\-file07
```

Password: `4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw`

## Level 5 → 6
```bash
find . -size +1032c -size -1034c
cat ./inhere/maybehere07/.file2
```
The `find` command is used to search for files and directories within a specified path based on different criteria.

Password: `HWasnPhtq9AVKe0dmk45nxy20cvUa6EG`

## Level 6 → 7
```bash
cd ../../
find . -size +32c -size -34c -group bandit6 -user bandit7 2>/dev/null
cat ./var/lib/dpkg/info/bandit7.password
```
The addition `2>/dev/null` is used to avoid getting `Permission denied` error lines.

Password: `morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj`

## Level 7 → 8
```bash
grep 'millionth' data.txt
```
The `grep` command is  used to streamline and automate text processing and data extraction tasks. Here it is used to find the lines that contain the word `millionth`.

Password: `dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc`

## Level 8 → 9
```bash
cat data.txt | sort | uniq -u
```
The `uniq` command neglect duplicate lines. By default, it will leave one line of each, so the `-u` flag do not leave any duplicate lines. Also, `uniq` only delete duplicagte lines that are following each other, which is why `sort` is needed. The `|` is called piping - it takes the output of the left and use it as the input for the right one.

Password: `4CKMh1JI91bUIZZPXDqGanal4xvAg0JM`

## Level 9 → 10
```bash
grep -a '===' data.txt
```
The `-a` flag is used to search binary files as text.

Password: `FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey`

## Level 10 → 11
```bash
cat data.txt | openssl enc -d -base64
```
`openssl` is a cryptography toolkit that supports many security-related tools. `enc` means encrypt/encode, `-d` means decode and `-base64` means to use the Base64 encoding scheme.

Password: `dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr`

## Level 11 → 12
```bash
cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```
The `tr` command is used to perform different text transformations. In that case, it replaces each of the characters specified in the first set with the characters from the second set that have the same position.

Password: `7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4`

## Level 12 → 13
```bash
mktemp -d
cp data.txt /tmp/tmp.3ilbAoM5US
cd /tmp/tmp.3ilbAoM5US
mv data.txt hex_data
```
`mktemp -d` create a unique temporary directory `/tmp/tmp.3ilbAoM5US/`, which has a random name. Then we copy `data.txt` to that dir, and rename it to `hex_data`. 

```bash
xxd -r hex_data data
cat ./hex_data
```
Now we start working with the data. `xxd -r` is used to revert the hexdump process, so we get the data in `data`. As said, the file has been repeatedly compressed, we have to decompress it. The first bytes of the file reveal what compression was used, so using [List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) we can find what method to use. We see that the first bytes of `hex_data` are `1f 8b 08`, so it's `GZIP` compression.

```bash
mv data data.gz
gzip -d data.gz
cat data
xxd data
```

We decompressed the data, but it is still compressed. By using `xxd` we see the first bytes of the file are now `42 5a 68`, so the compression type is `Bzip2`. 

```bash
mv data data.bz2
bzip2 -d data.bz2 
cat data
xxd data
```
Again, The data is still compressed. The first bytes are now `1f 8b 08` again, so we decompress it using `GZIP`, Again.

```bash
mv data data.bz2
bzip2 -d data.bz2 
cat data
xxd data | head
```

Now the first bytes does not match any compression method, but by doing `cat data` we can see that it starts with `data5.bin`, which is a name of a file. It means it might be an archive, so we have to use `tar` to extract it.

```bash
mv data data.tar
tar -xf data.tar
ls
cat data5.bin
```
After extracting, there is a new file in the directory called `data5.bin`. It starts with another file name, `data6.bin`, so we use `tar` again.

```bash
tar -xf data5.bin
ls
cat data6.bin
xxd data6.bin
```
We now have a new file `data6.bin`. after using `cat` it still looks compressed, and using `xxd` we can see that the first bytes are `42 5a 68` again, so we decompress it using `Bzip2`.

```bash
mv data6.bin data6.bin.bz2
bzip2 -d data6.bin.bz2
cat data
```
Now the data starts with another file name `data8.bin`, so we extract again using `tar`.

```bash
tar -xf data6.bin
ls
cat data8.bin
xxd data8.bin
```
`data8.bin` starts with `1f 8b 08`, so we use `GZIP` again.

```bash
mv data8.bin data8.gz
gzip -d data8.gz
cat data8
```
Finally we have a readable file `data8`

Password: `FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn`

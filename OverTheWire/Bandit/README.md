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


## Level 13 → 14
```bash
ls
logout
```
After logging in, there is only one file `sshkey.private`, and it's location is known to us now.
We will use this ssh key to access user `Bandit14`, but we need a copy on our machine.

**The following commands are on our machine, not using the remote connection**
```bash
scp -P 2220  bandit13@bandit.labs.overthewire.org:sshkey.private .
chmod 700 sshkey.private
ssh -i ./sshkey.private  bandit14@bandit.labs.overthewire.org -p 2220
```
`scp` is used to securely copy files from a remote host, using encrypted ssh connection. We copy the file, but it's permissions are wrong, the permissions were set on the host and give an error message when trying to use `ssh` here. So we change it by using `chmod` and then we log into `bandit14`, using the `-i` flag to use a private key.

```bash
cat /etc/bandit_pass/bandit14
```
After logging in, we can find the password on the file that only `Bandit14` can access.

Password: `MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS`

## Level 14 → 15
```bash
nc localhost 30000
MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS
```
The `nc` command is used for reading a writing data between two networks. We use it to send the password of `Bandit14` to `localhost` at port `30000`, and we get back the next password.

Password: `8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo`

## Level 15 → 16
```bash
openssl s_client -connect localhost:30001
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
```
`s_client` command on `openssl` is using `SSL/TLS` in order to connect to a remote host. The `-connect` flag is used to state the `host:port`.

Password: `kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx`

## Level 16 → 17
```bash

```

`nmap` is a network scanner. It has many uses, but here it is used to scan ports. The `-p` flag is used to search in a port range, and `-sV` flag does a service/version scan. After a little while the scan ends and we get this:
```bash
Not shown: 995 closed tcp ports (conn-refused)
PORT      STATE SERVICE     VERSION
31046/tcp open  echo
31518/tcp open  ssl/echo
31691/tcp open  echo
31790/tcp open  ssl/unknown
31960/tcp open  echo
32000/tcp open  tcpwrapped
```
So there are 6 used (open) ports, but only 2 of them use `SSL` protocol. But we can see that port `31518` is only using the echo service, so the port we need is `31790`.

```bash
openssl s_client -connect localhost:31790 -quiet
```
We need the `-quiet` flag because otherwise we get a `KEYUPDATE` error. The server returns a `RSA` private key, we save it on a file on our machine for the next level.

## Level 17 → 18
```bash
chmod 700 ./Bandit17/sshkey.private
ssh -i ./Bandit17/sshkey.private  bandit17@bandit.labs.overthewire.org -p 2220
ls
diff passwords.old passwords.new
```
The connection is with the `RSA` private key we saved. We see the 2 files, and use `diff` to compare them.

Password: `x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO`

## Level 18 → 19
```bash
ssh bandit18@bandit.labs.overthewire.org -p 2220 ls
ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme
```
Using `ssh`, it is possible to only execute a command on the host machine. 

Password: `cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8`

## Level 19 → 20
```bash
./bandit20-do
./bandit20-do id
./bandit20-do ls /etc/bandit_pass
./bandit20-do cat /etc/bandit_pass/bandit20
```
First, we run the file with no arguments. It says `Run a command as another user. Example: ./bandit20-do id`, so we then run it to find out we can read as `Bandit20`. We use `cat` to read the next level password in `/etc/bandit_pass/bandit20`

Password: `0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO`

## Level 20 → 21
```bash
echo -n '0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO' | nc -l 55555 &
./suconnect 55555
```
We need to set a server on the `localhost`, on any port, that will send back to anyone the password of `Bandit20`. 
* `echo` is used to send back the password when a connection is established. `-n` is used to avoid a new line.
* `|` is a pipe, as used in previous levels.
* `nc` is used to make the server, `-l` sets it to listen on port `55555`.
* `&` is used to run that task in the background, so we're able to run another command.
Then by using the given exec with port `55555` as the input, it connects and gets back the password of `Bandit20` from the server, so it sends the next password.

Password: `EeoULMCra2q0dSkYj561DX7s1CpBuOBt`

## Level 21 → 22
```bash
cd /etc/cron.d
ls
cat cronjob_bandit22
cat /usr/bin/cronjob_bandit22.sh
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```
We go to the given directory `cron.d` and see the file `cronjob_bandit22`. `cronjobs` are programs that run in the background at a specific time. The file looks like this:
```bash
@reboot bandit24 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit22.sh &> /dev/null
```
The second line indicates that the program runs every minute on every day, and it runs the bash file `/usr/bin/cronjob_bandit22.sh`. The file looks like this:
```bash
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```
It makes a file in `/tmp` so that everyone can read it, then it copies the password of `Bandit22` to another file. So by printing the file `/tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv` we find the next password.

Password: `tRae0UfB9v0UzbCdn9cY0gQnds9GF58Q`

## Level 22 → 23
```bash
cd /etc/cron.d
ls
cat cronjob_bandit23
cat /usr/bin/cronjob_bandit23.sh
```
The same as previous level. Here is the content of the file:
```bash
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
```
`myname=$(whoami)` runs the `whoami` command and sets `mytarget` as the output of that command, so it equals `bandit22`. So it copies the password of `Bandit22` to the file, but we want the password for `Bandit23`. Trying to edit the bash file fails, we do not have permission for that.

```bash
echo I am user bandit23 | md5sum | cut -d ' ' -f 1
cat /tmp/8ca319486bfbbc3663ea0fbe81326349
```

We can see that the target file, `mytarget`, is created by `$(echo I am user $myname | md5sum | cut -d ' ' -f 1)`. It means that it takes the `md5` hash of the string `"echo I am user $myname"` and that is the file containing the nexp password. The left command removes everything after a space. So by running that command with `bandit23` as `$myname`, we get the file's name inside `/tmp/`. Since it is a `cronjob`, the files is created every minute, so it exist and we can read it.

Password: `0Zf11ioIjMVN551jX3CmStKLYqjk54Ga`

## Level 23 → 24
```bash
cd /etc/cron.d
ls
cat cronjob_bandit23
cat /usr/bin/cronjob_bandit23.sh
```
This time the file looks like this:
```bash
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname/foo
echo "Executing and deleting all scripts in /var/spool/$myname/foo:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done
```
The script deletes all files in `/var/spool/bandit24/foo`, except for `.` and `..`, if the owner is `bandit23`. 

```bash
mktemp -d
cd /tmp/tmp.lQG5yjwLol
nano shellcode.sh
touch bandit24_pass.txt
```
We need to create a shellcode file, then if we move it to `/var/spool/bandit24/foo` it will be executed. We will make the output file and the following shellcode called `shellcode.sh` in a new temp directory using the `nano` command:
```bash
#!/bin/bash

cat /etc/bandit_pass/bandit24 > /tmp/tmp.lQG5yjwLol/bandit24_pass.txt
```
As seen in previous levels, the password for `Bandit24` is in `/etc/bandit_pass/bandit24`.

```bash
ls -l
chmod 777 bandit24_pass.txt 
chmod +rx shellcode.sh 
chmod 777 /tmp/tmp.lQG5yjwLol
cp shellcode.sh /var/spool/bandit24/foo
cat bandit24_pass.txt
```
We change the permissions of the directory and files so that `Bandit24` will be able to execute out shellcode. Then we copy the shellcode into `/var/spool/bandit24/foo`, it executed and we get the password in `bandit24_pass.txt`.

Password: `gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8`

## Level 24 → 25
```bash
mktemp -d
cd /tmp/tmp.6YQM311NSk
nc localhost 30002
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8 1234
nano shellcode.sh
```
We make a new temp file to work there, and we try to connect and send a message to the server. When connected with `nc`, the server introduce itself and states the expected input. When given the wrong pin code, it responsed with `Wrong! Please enter the correct current password and pincode. Try again.`. We make a new shellcode `shellcode.sh` with that content:
```bash
#!/bin/bash

for i in {0000..9999};
do
        echo gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8  $i >> pincodes.txt
done

cat pincodes.txt | nc localhost 30002 > response.txt
```
This program goes through all the possible pincodes and put them with the password in `pincodes.txt`. Then it connects to the server and sends the password and all possible pincodes. It is a **Brute Force** approach.

```bash
./shellcode.sh
ls
grep -v Wrong response.txt
```
We run the shellcode and see the files have been created. Lastly, we know that when the input is wrong, the server response starts with 'Wrong!', so we want to see all the lines that do not contain it in `responses.txt`. One of them was indeed the next password.

Password: `iCi86ttT4KSNe1armKiwbQNmB3YJP3q4`

## Level 25 → 26
```bash
ls
logout
```
After logging in, there is only one file `bandit26.sshkey`, which is the `RSA` key for `Bandit26`. 

**The following commands are on our machine, not using the remote connection**
```bash
mkdir Bandit26
scp -P 2220 bandit25@bandit.labs.overthewire.org:bandit26.sshkey ./Bandit26
ssh -i ./Bandit26/bandit26.sshkey bandit26@bandit.labs.overthewire.org -p 2220 
```
As on previous levels, we copy the file from the host to our machine using `scp`, and tring to connect to `Bandit26` with the key, using `ssh -i`. The remote gives a generic welcome message and closes the connection. Trying to directly run commands does not work, it just returns a generic message.

We log into `Bandit25` again using `ssh`.
```bash
cat /etc/passwd | grep bandit26
ls -l /usr/bin/showtext
cat /usr/bin/showtext
```
Every user has his own default shell, and the info about the specific shell is written in `/etc/passwd` for every user, at the end of the line. So we print it using `grep` and find it is in `/usr/bin/showtext`. The file looks like this:
```bash
#!/bin/sh

export TERM=linux

exec more ~/text.txt
exit 0

```
The `more` command is a tool for viewing text files in the terminal. So, when we connect to `Bandit26`, `showtext` is executed and shows the text inside `text.txt` and then closes the connection. `more` is used to view one page of a text file at a time. `text.txt` is short, so it fits in one page, but if we rescale the terminal window it won't. Now we rescale the terminal to be small and do this:

```bash
ssh -i ./Bandit26/bandit26.sshkey bandit26@bandit.labs.overthewire.org -p 2220 
v
:set shell=/bin/bash
:shell
```
Because the text now doesn't fit, we hit `v` to go into `Vim` mode and edit the file. Now we have access to `Vim` on the target machine, so we set the default shell to `/bin/bash` using `:set` command and then by using `:shell` we have access to the shell on the target machine.

```bash
ls
./bandit27-do
```
We now see that there is a file called `bandit27-do`. when we run it we get the prompt:
```bash
run a command as another user.
  Example: ./bandit27-do id
```
So it must be for the next level.
```bash
cat /etc/bandit\_pass/bandit26
```
We are using the shell as `Bandit26`, so we can access it's password.

Password: `s0773xxkk0MXfdqOfPRVr9L3jJBUOgCZ`

## Level 26 → 27
```bash
/bandit27-do id
/bandit27-do cat /etc/bandit\_pass/bandit2
```
As we are still using the shell as `Bandit26`, we have access to `bandit27-do` that runs a command as `Bandit27`, and therefore have an access to it's password.

Password: `upsNCc7vzaRDx6oZC6GiR6ERwe1MowGB`

## Level 27 → 28
```bash
ls
cd /home/bandit27-git/repo

```
As we log into `Bandit27`, there are no files and no permission for `/home/bandit27-git/repo`.

```bash
mktemp -d
cd /tmp/tmp.YUU9waKZ1A
git clone ssh://bandit27-git@localhost:2220/home/bandit27-git/repo
cd repo
ls -l
cat README
```
We create a temp and clone the repository inside `/home/bandit27-git/repo`. There we find a file `README` with the next password.

Password: `Yz9IpL0sBcCeuG7m9uQFt8ZNpS4HZRcN`

## Level 28 → 29
```bash
mktemp -d
cd /tmp/tmp.ShXRPVv7YI
git clone ssh://bandit28-git@localhost:2220/home/bandit28-git/repo
cd repo
ls -l
cat README.md
```
This is the same as the last level. But now `README.md` contains this:
```bash
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: xxxxxxxxxx
```
The file contains the password, but not really. We can check the previous versions, maybe in one of them the password exists.
```bash
git log
```
As we look at the versions, we notice these commits:
```bash
commit 674690a00a0056ab96048f7317b9ec20c057c06b (HEAD -> master, origin/master, origin/HEAD)
Author: Morla Porla <morla@overthewire.org>
Date:   Thu Apr 10 14:23:19 2025 +0000

    fix info leak

commit fb0df1358b1ff146f581651a84bae622353a71c0
Author: Morla Porla <morla@overthewire.org>
Date:   Thu Apr 10 14:23:19 2025 +0000

    add missing data
```
'info leak' might be the password. We can check the difference between them to see what 'info leak' was fixed.
```bash
git diff 674690a00a0056ab96048f7317b9ec20c057c06b~ 674690a00a0056ab96048f7317b9ec20c057c06b
```
This way we can view the diff between the commit `674690a00a0056ab96048f7317b9ec20c057c06b` and it's previous version, which is what `~` does. 
```bash
diff --git a/README.md b/README.md
index d4e3b74..5c6457b 100644
--- a/README.md
+++ b/README.md
@@ -4,5 +4,5 @@ Some notes for level29 of bandit.
 ## credentials
 
 - username: bandit29
-- password: 4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7
+- password: xxxxxxxxxx
```
We now can see the password for the next level that has been 'fixed'.

Password: `4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7`

## Level 29 → 30
We clone the repository to a temp directory, as we did in the last 2 levels.
Now `README.md` contains this:
```bash
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: <no passwords in production!>
```
The password is not here. But, we can see that the password exist in another file, but not in production, which means not on the master branch.
```bash
git log -p
git branch -a
```
We check all the changes between commits on the master, nothing here. But if we check all the branches, with `branch -a`, we get this:
```bash
* master
  remotes/origin/HEAD -> origin/master
  remotes/origin/dev
  remotes/origin/master
  remotes/origin/sploits-dev
```
These are all the branches in that repo. From the line `- password: <no passwords in production!>` we are not intrested in the production, we want the `dev` branch.
```bash
git checkout remotes/origin/dev
ls
cat README.md
```
By using `checkout remotes/origin/dev`, we access the `dev` branch and therefore it's files. We print the `README.md` file in this branch:
```bash
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: qp30ex3VLz5MDG1n91YowTv4Q8l7CDZL

```
And there is the next password.

Password: `qp30ex3VLz5MDG1n91YowTv4Q8l7CDZL`

## Level 30 → 31
We first clone the repo as before. This time the `README.md` says:
```bash
just an epmty file... muahaha
```
Very unuseful and has a typo.

```bash
git log -p
git branch -a
git checkout remotes/origin/master
git log -p
```
There is only an initial commit with the `README.md` file in it in all of the branches.
```bash
git tag
git show secret
```
In Git, tags are a way to mark points in the repo's history. Every tag references a specific commit within the project history. A tag has a `name` and a `message`. By using `git tag` we can see all the tags of this repo. We find a tag with the name `secret`, so by using `git show` we view it's message, which is the next password.

Password: `fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy`

## Level 31 → 32
After cloning the repo, `README.md` says:
```bash
This time your task is to push a file to the remote repository.

Details:
    File name: key.txt
    Content: 'May I come in?'
    Branch: master
```
So our task is to push a file as it says.
```bash
ls -la
cat .gitignore
```
We notice the file `.gitignore` in the repo. That file tells Git to automatically ignore specific files or files that fit specific formats. This file contains the format `*.txt`, which means to ignore every file that ends with `.txt`.
```bash
rm .gitignore
echo 'May I come in?' > key.txt
git commit -am "..."
git push
```
First, we remove `.gitignore`. Then creating `key.txt` as specified, commiting and pushing. In return, we get the next password.

Password: `3O9RfhqyAlVBEZpVb6LYStshZoqoSx5K`

## Level 32 → 33
After logging in, we get to an `UPPERCASE SHELL`. Trying to execute some commands isn't working.

```bash
WELCOME TO THE UPPERCASE SHELL
>> PWD
sh: 1: PWD: Permission denied
>> whoami
sh: 1: WHOAMI: Permission denied
>> echo asd
sh: 1: ECHO: Permission denied
>> ???
sh: 1: ???: Permission denied
```
Looks like we do not have permission to use the `SHELL`.
```bash
>> $user
sh: 1: bandit32: Permission denied
>> $path
sh: 1: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin: not found
>> $home
sh: 1: /home/bandit32: Permission denied
```
In `bash`, variables are accessed by using `$VAR`, which means the variable in caps and `$`. We can see that we can trick the `UPPERCASE SHELL` to show us system variables suck as what user is running the commands.

```bash
>> $0
```
`$0` is the path of the current user's shell. Because `$0` in uppercase stays the same, the program executes the shell, so now we have full access to the shell with the user's permissions.

```bash
cat /etc/bandit\_pass/bandit33 
```
As seen in previous levels, the passwords are in `/etc/bandit_pass/`. So we use the terminal we now access to see the next password.

Password: `tQdtbs5D5i2vJwkO8mEyYEyTL8izoeJ0`

## Level 33 → 34
**At this moment, level 34 does not exist yet.**

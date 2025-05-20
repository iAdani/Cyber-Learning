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

Password: dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc

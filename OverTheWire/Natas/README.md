# Natas Wargame

This repository tracks my progress through the Natas wargame by OverTheWire. Natas is focused on web security, covering a wide range of real-world web vulnerabilities including authentication bypasses, information disclosure, input manipulation, client/server-side logic flaws, and basic web exploitation techniques.

Each level is a hosted web page with a challenge that can be solved using tools like browser developer tools, curl, Burp Suite, and basic scripting. I’ll document each level with steps, explanations, and any payloads used. Some levels may be solved with hints or public write-ups, but I’ll always explain the solution in my own words.

## Level 0 → 1
We log in as `Natas0`, and the website says `"You can find the password for the next level on this page."`. We hit `F12` to open the developer tools, and in the `HTML` of the page we can see a `div`, inside it we find the next password.

Password: `0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq`

## Level 1 → 2
This time the website says the same thing, but rightclicking is blocked. We do the same as previous level and get the password.

Password: `TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI`

## Level 2 → 3
The website says `There is nothing on this page`. But looking at the `HTML`, we notice this tag:
```html
<img src="files/pixel.png">
```
The `img` tag is used to display images, and `src` is the source of the image. We can see that it displays `pixel.png` which is in a directory called `files`. We try to go to the path `/files` in that website, like that:
```
http://natas2.natas.labs.overthewire.org/files/
```
It works and we can see some files, one of them is `users.txt`. Clicking on it shows it's content, which is usernames and their passwords, and one of them is `Natas3`.

Password: `3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH`

## Level 3 → 4
We log in, and the website says the same. But this time there's no `img` tag, there is a comment saying
```html
<!-- No more information leaks!! Not even Google will find it this time... -->
```
This is a hint. In many websites, there is a file called `robots.txt` that tells Google's crawlers what parts of the websites they should crawl. So we visit the path `/robots.txt` and see this:
```
User-agent: *
Disallow: /s3cr3t/
```
It means that all crawlers should avoid the path `/s3cr3t/`. We go into that path, and find a file called `users.txt`, and inside it we find the next password.

Password: `QryZXc2e0zahULdHrtHxzyYkj59kUxLQ`
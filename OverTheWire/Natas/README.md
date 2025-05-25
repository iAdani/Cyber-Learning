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

## Level 4 → 5
We log in and the website says `authorized users should come only from "http://natas5.natas.labs.overthewire.org/"`. We don't have access to `Natas5` yet, so we need to trick the website into thinking that we were refered to this site from the specified address.

### `curl` command
`curl` (Client URL) is a CLI tool for transfering data by communicating web or application servers over popular network protocols, like `HTTP`, `HTTPS`, `FTP` and more. 

An HTTP request has the option to include information about which address referred it to the actual page. The `curl` command allows us to specify a referrer using the `-e` flag. Another useful flag is `-u`, it let's us specify username and password for our request. We first use this command on our terminal:
```bash
curl -e http://natas5.natas.labs.overthewire.org/ http://natas4.natas.labs.overthewire.org/
```
But the response says `401 Unauthorized`, so we need to add the username and password.
```bash
curl -u natas4:QryZXc2e0zahULdHrtHxzyYkj59kUxLQ -e http://natas5.natas.labs.overthewire.org/ http://natas4.natas.labs.overthewire.org/
```
Now we get access to the website, which gives us the next password.

Password: `0n35PkggAPm2zbEpOU802c0x0Msn1ToK`

## Level 5 → 6
This time the website says `Access disallowed. You are not logged in`, which is weird because we just logged in.

### HTTP Cookies
`HTTP cookies` are small text file that websites store on the user's browser. They help websites to remember information about the user in order to personalize, track activity and preferences. But more importently, they are used for login processes.

In our case, even though we logged in, the website doesn't recognize that we are logged in. To track if a user is logged in, websites mainly use `HTTP cookies`, so that's what we should check. In the developer tools we can see the `storage` tab, and inside we can see the website's cookies. There is one cookie here, and it has a field called `loggedin`, which is set to `0`. We change it to `1` and refresh, and now the website knows we are logged in and the next password is revealed.

Password: `0RoJwHdSKWFTYR5WuiAewauSuNaBXned`

## Level 6 → 7
This time we need to find a secret input. There is also a link to view the sourcecode, so we check it and we can see that function:
```php
<?

include "includes/secret.inc";

    if(array_key_exists("submit", $_POST)) {
        if($secret == $_POST['secret']) {
        print "Access granted. The password for natas7 is <censored>";
    } else {
        print "Wrong secret";
    }
    }
?>
```

### PHP Language
`PHP` (Hypertext Preprocessor) is a scripting language that is very popular for server-side in websites. It allows developers to embed dynamic code within HTML.  When a user visits a PHP-enabled page, the server processes the PHP code and sends the resulting HTML output to the browser. PHP is widely used for creating dynamic websites, handling forms and connecting to databases. It is enclosed in `<?php ... ?>` tags (possible without `php`, like in our example), variables start with `$` and the content of forms sent by `POST` request can be used with the `$_POST` variable.

As we can see by the `<? ... ?>` tags, the above function is wriiten in `PHP`. That's why by viewing the sourcecode in the developer tools, we can't see this function. 

Inside the function, we can see the line `include "includes/secret.inc";`. It means that a file named `includes/secret.inc` exist. We want to check it out, so we go to the path `/includes/secret.inc` and view its source code, and there is a comment with the secret input. We go back and submit the secret code, and we get the next password.

Password: `bmg8SvU1LizuWjx3y7xkNERkHxGre0GS`

## Level 7 → 8
This time there are 2 links on the page, `Home` and `About`. By clicking on Home, it adds `?page=home` to the url and displays a text saying `this is the front page`. It does a similar thing with About.

### Path Traversal Attack
`Path traversal` attack is a security vulnerability of websites that allows the attacker to access files and directories outside the website's file system location. It is done by manipulating input paths on the website. When using unintended paths, like `../` or `/etc/` for example, the attacker can travel inside the directory hierarchy and access sensitive info, such as passwords, system data and configuration files that should be restricted. This can be avoided by validating the file related operations on the server.

When viewing the page's source code, there is a hint comment:
```HTML
<!-- hint: password for webuser natas8 is in /etc/natas_webpass/natas8 -->
```

So we want to use `Path traversal` to see the password on that path. As we've seen, the website uses `?page=` in order to view the content of `home` and `about`, that might be files in the server's directory. So by using the path `http://natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8`, we travel to the user's password file and get the next password.

Password: `xcoXLmzMkoIP9D7hlgPlh9XD7OgLAe5Q`
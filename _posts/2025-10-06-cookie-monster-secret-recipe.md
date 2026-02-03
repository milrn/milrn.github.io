---
author: milrn
categories:
- picoCTF
- Web Exploitation
- Easy
layout: post
media_subpath: /assets/posts/2025-10-06-cookie-monster-secret-recipe
tags:
- picoCTF 2025
- Cookies
- Base64
- Inspect Element
- Easy
title: Cookie Monster Secret Recipe
description: Cookie Monster Secret Recipe is an Easy Web Exploitation challenge from picoCTF 2025. It has almost 30,000 user solves as of writing this.
---

![](cookie_monster_secret_recipe.png)

Cookie Monster Secret Recipe is an Easy Web Exploitation challenge from picoCTF 2025. It has almost 30,000 user solves as of writing this.

# Website

When I visited the website, it showed a default login page.

![](web_page.png)

# Login Attempt

I tried the test credentials "cookie, cookie" while inspecting network requests.

![](try_login.png)

![](login_response.png)

# Getting the Flag

When inspecting the request sent to the server, I noticed that there was a "secret_recipe" cookie being attached. This cookie immediately looked base64 encoded, so I tried to decode it using the base64 command.

```
echo 'cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzXzQ3MzZGNkNCfQ==' | base64 -d
```

This successfully printed the flag!

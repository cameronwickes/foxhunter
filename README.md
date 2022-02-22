<h1 align="center">
  <img alt="foxhunter logo" src="https://raw.githubusercontent.com/cameronwickes/foxhunter/main/logo.png" width="224px"/><br/>
  FoxHunter
</h1>

<p align="center">
<img alt="Supported Platforms" src="https://img.shields.io/badge/Platform-Linux-blueviolet?color=blue&style=for-the-badge">
<img alt="Language" src="https://img.shields.io/badge/Language-Python-blue?color=blueviolet&style=for-the-badge">
<img alt="GitHub file size in bytes" src="https://img.shields.io/github/size/cameronwickes/foxhunter/foxhunter.py?color=brightgreen&style=for-the-badge">
<img alt="License" src="https://img.shields.io/github/license/cameronwickes/foxhunter?color=blue&style=for-the-badge">
</p>

<p align="center">
A tool for <b>extracting</b>, <b>analysing</b>, <b>attacking</b>, and <b>dumping</b> Firefox browser artifacts on Linux platforms for forensic purposes. 

FoxHunter extracts and dumps:
<ul>
<li>Addons</li>
<li>Bookmarks (Active & Deleted)</li>
<li>Browsing History</li>
<li>Browsing History Searches</li>
<li>Certificates (x509)</li>
<li>Cookies</li>
<li>Downloads</li>
<li>Extensions</li>
<li>Form History</li>
<li>Saved Logins (Encrypted)</li>
</ul>

<br/>

FoxHunter allows users to decrypt extracted logins through:
<ul>
<li>Anonymous Authentication (Blank Password)</li>
<li>Password Authentication (Known Factor)</li>
<li>Brute Force Authentication (Wordlist/Dictionary Attack)</li>
</ul>

<br/>

Finally, FoxHunter performs analysis on gathered artifacts:
<ol>
<li>Identifies addons not installed through Mozilla store.</li>
<li>Identifies addons with low download rates and/or ratings.</li>
<li>Identifies out-of-date addons - potential security risks.</li>
<li>Identifies extensions with interesting/abnormal permissions.</li>
<li>Identifies certificates from relatively unknown issuers.</li>
<li>Identifies certificates with weak/unrecommended encryption standards.</li>
<li>Categorises bookmarks by site type.</li>
<li>Identifies downloads with interesting file names.</li>
<li>Identifies common file download websites.</li>
<li>Categorises downloads by file type.</li>
<li>Produces graphs of user downloads per day.</li>
<li>Identifies interesting form history fields - logins, usernames, passwords, phone numbers, addresses, commands.</li>
<li>Identifies the top 5 most commonly used form fields, and their values.</li>
<li>Identifies commonly used login usernames and passwords.</li>
<li>Identifies cookies with interesting values.</li>
<li>Identifies the 5 most common browsing history searches.</li>
<li>Produces graphs of browser usage over time.</li>
<li>Produces graphs of site browsing habits.</li>
</ol>

</p>
<br/>

## ⚡️ Quick start

First, install **Python 3** and **Pip**.

```
sudo apt-get update
sudo apt-get install python3.10
sudo apt-get install python3-pip
```

Install the required dependencies for FoxHunter, using `pip`.

`pip install -r requirements.txt`

To verify that dependencies have been installed correctly, run FoxHunter.

`python3 foxhunter.py -h`

## 🦊 Commands & Options


## ⚖️ License

`FoxHunter` is free and open-source software licensed under the [MIT License](https://github.com/cameronwickes/foxhunter/blob/main/LICENSE).

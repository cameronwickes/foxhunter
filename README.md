<h1 align="center">
  <img alt="foxhunter logo" src="https://raw.githubusercontent.com/cameronwickes/foxhunter/main/logo.png" width="224px"/><br/>
  FoxHunter
</h1>

<p align="center">
<img alt="Supported Platforms" src="https://img.shields.io/badge/Platform-Linux-blueviolet?color=blue&style=for-the-badge">
<img alt="Language" src="https://img.shields.io/badge/Language-Python-blue?color=blueviolet&style=for-the-badge">
<img alt="GitHub file size in bytes" src="https://img.shields.io/github/size/cameronwickes/foxhunter/foxhunter.py?color=brightgreen&style=for-the-badge">
<img alt="License" src="https://img.shields.io/github/license/cameronwickes/foxhunter?color=blue&style=for-the-badge">
<img alt="GitHub Workflow Status" src="https://img.shields.io/github/workflow/status/cameronwickes/foxhunter/Test%20Integration?style=for-the-badge">
</p>

<p align="center">
A tool for <b>extracting</b>, <b>analysing</b>, <b>attacking</b>, and <b>dumping</b> Firefox browser artifacts on Linux platforms for forensic purposes. 
</p>
<br/>
<p>
<b>FoxHunter extracts and dumps:</b>
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

<b>FoxHunter allows users to decrypt extracted logins through:</b>
<ul>
<li>Anonymous Authentication (Blank Password)</li>
<li>Password Authentication (Known Factor)</li>
<li>Brute Force Authentication (Wordlist/Dictionary Attack)</li>
</ul>

<br/>

<b>Finally, FoxHunter performs analysis on gathered artifacts:</b>
<ul>
<li>Identifies addons not installed through Mozilla store.</li>
<li>Identifies addons with low download rates and/or ratings.</li>
<li>Identifies out-of-date addons - potential security risks.</li>
<li>Identifies extensions with interesting/abnormal permissions.</li>
<li>Identifies certificates from relatively unknown issuers.</li>
<li>Identifies certificates with weak/unrecommended encryption standards.</li>
<li>Identifies deleted bookmarks.</li>
<li>Identifies possible malware downloads by file name.</li>
<li>Identifies common file download websites.</li>
<li>Categorises downloads by file type.</li>
<li>Produces graphs of user downloads over extended periods of time.</li>
<li>Identifies interesting form history fields containing PII.</li>
<li>Identifies commonly used form fields.</li>
<li>Identifies commonly used login usernames and passwords.</li>
<li>Identifies potential patterns within usernames or passwords.</li>
<li>Identifies cookies with interesting values (Base64, Hex, GA Cookies).</li>
<li>Identifies the most common browsing history searches.</li>
<li>Identifies common browsing history searches.</li>
<li>Identifies commonly used search engines.</li>
<li>Identifies commonly used social media sites.</li>
<li>Identifies times of the day when the user is most active.</li>
<li>Identifies days of the week when the user is most active.</li>
</ul>

</p>
<br/>

## ?????? Quick start

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

<br/>

## ???? Commands & Options

By default, FoxHunter extracts artifacts from a profile, and displays statistics about gathered artifacts on the terminal.

- A specific Firefox profile can be specified with the `-p` argument. If this argument is not supplied, FoxHunter will attempt to search the system for Firefox profiles, and let the user choose.
- To dump gathered artifacts out, use any of the `-oC`, `-oJ` or `-oX` arguments to dump in CSV, JSON and XML formats respectively.
- To perform additional analysis of artifacts, specify the `-A` argument. This requires an Internet connection.

```
$ python3 foxhunter.py -h

usage: foxhunter.py [-h] [-q] [-p PROFILE] [-oC OUTPUT_DIR] [-oJ OUTPUT_DIR] [-oX OUTPUT_DIR] [-A]

options:
  -h, --help                                 show this help message and exit
  -q, --quiet                                don't display debug messages
  -p PROFILE, --profile PROFILE              directory of firefox profile to seek artifacts
  -oC OUTPUT_DIR, --output-csv OUTPUT_DIR    directory to dump artifacts in CSV format
  -oJ OUTPUT_DIR, --output-json OUTPUT_DIR   directory to dump artifacts in JSON format
  -oX OUTPUT_DIR, --output-xml OUTPUT_DIR    directory to dump artifacts in XML format
  -A, --analyse                              analyse gathered artifacts
```

<br/>

## ???? Testing

FoxHunter is tested using the [bash-tap](https://github.com/wbsch/bash_tap) testing framework.

To run all tests, execute `./test`. In order for a test to be picked up by this program, it must have:
- An extension of `.t`.
- Executable permissions. (`chmod +x test.t`)

To verify the program is working as intended, a set of pregenerated testing profiles are used. These can be found at `testing/data/profile-no-password` and `testing/data/profile-password`. 

Saved login data for the former profile is unlocked. Saved login data for the latter is protected using the master password in `testing/data/master-password`, which can also be obtained using the `getPassword` function within tests.

**NOTE:** Testing is done on GitHub runners with a UTC timezone. If you attempt to test on a machine that is not running on UTC time, tests may fail.
<br/>

## ?????? License

`FoxHunter` is free and open-source software licensed under the [MIT License](https://github.com/cameronwickes/foxhunter/blob/main/LICENSE).

akabe1-semgrep-rules
============================

# Description 
The akabe1-semgrep-rules are a collection of my custom Semgrep rules, built to speed-up source code analysis activities.

They provide various additional patterns useful to detect vulnerabilities, which could be used in combination with the official Semgrep rules in order to reduce the percentage of false negatives.


# Usage
To use these rules is needed first to install Semgrep tool, from the official github repo [Semgrep](https://github.com/returntocorp/semgrep), or alternatively download Semgrep docker image.

Then clone this github repo, and finally run any of these commands:

1. Run multiple rules in a folder
```
semgrep --config akabe1-semgrep-rules/<SUBFOLDER>/
```
2. Run single rule in a file
```
semgrep --config akabe1-semgrep-rules/<SUBFOLDER>/<FILE>.yaml
```


# Features
Below a non-exhaustive list of the rules included in this repo:

**Swift**

* Certificate Pinning issues
* Biometric Authentication issues
* XXE
* SQL Injection issues
* Crypto issues
* Log Injection issues
* NoSQL Injection issues
* WebView issues
* Insecure Storage issues
* Keychain Settings issues
* and others..

# Note
Currently the support of Swift language on Semgrep is in experimantal phase, this could cause false negatives.


# Author
- akabe1-semgrep-rules were written by Maurizio Siddu


# GNU License
Copyright (c) 2023 akabe1-semgrep-rules

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>


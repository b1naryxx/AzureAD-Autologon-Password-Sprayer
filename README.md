# AzureAD-Autologon-Password-Sprayer
Multi-thread AzureAD Autologon SSO Password Sprayer.

This is a multi-thread tool that allows you to perform a password spraying or even user enumeration on AzureAD abusing the Azure Active Directory Seamless Single Sign-On feature as reported by Secureworks on https://www.secureworks.com/research/undetected-azure-active-directory-brute-force-attacks


```
Requirements:
beautifulsoup4
lxml
```

```
Usage: aad_sprayer.py -u users.txt -p Password123

Results will be stored in the "results" folder. Use the --save-all feature to save a list of existing accounts if you want to perform a user enumeration.

arguments:
  -h, --help            show this help message and exit
  -u USERS, --users USERS
                        File with users
  -p PASSWORD, --password PASSWORD
                        Password to test
  -o OUTPUT, --output OUTPUT
                        Output file. Default is out.txt
  -a, --save-all        Save all the information found in different files (locked accounts in locked.txt, disabled accounts in disabled.txt, non-existent accounts in
                        nonexistent.txt, mfa accounts in mfa.txt, existent accounts in existing.txt)
  -t THREADS, --threads THREADS
                        Maximum number of threads to use. Default 32
  -d DEBUG, --debug DEBUG
                        Enable debug mode
  -s THRESHOLD, --threshold THRESHOLD
                        Set a safe threshold to stop execution after a number of locked accounts is found. Default is 0
                        
```

# To-Do
 - Add Proxy support
 - Fix error code AADSTS81016 (undocumented error)
 - Clean up code

> # </[Cert-Thief](https://github.com/reslaid/xargs.git)> [![Version](https://img.shields.io/badge/Version-0.2.1-red.svg)](https://github.com/reslaid/xargs.git) [![language](https://skillicons.dev/icons?i=rust)](https://github.com/reslaid/xargs.git)
- > **This program allows you to transfer an application certificate to another executable application.**

# Usage
## Embedding
**Embedding a digital signature from another PE structure file**
```bash
thief.exe <source> --impl <target>
```

## Extracting
**Extract a certificate from any file with a PE structure into .crt**
```bash
thief.exe <source> --pull <cert>
```

## Placing
**Place the certificate from .crt in any PE structure file**
```bash
thief.exe <target> --sew <cert>
```

## Removing
**Remove certificate from PE structure file**
```bash
thief.exe <target> --delete
```

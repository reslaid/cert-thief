> # </[Cert-Thief](https://github.com/reslaid/xargs.git)>
> [![Version](https://img.shields.io/badge/version-0.2.2-red.svg)](https://github.com/reslaid/xargs.git) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/59f8c24c9440417782b450854839c284)](https://app.codacy.com/gh/reslaid/cert-thief/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade) <img src="https://skillicons.dev/icons?i=rust" alt="Language: Rust" style="width:20px;height:20px;">
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

> # </[Cert-Thief](https://github.com/reslaid/xargs.git)>
> [![Version](https://img.shields.io/badge/version-0.2.2-red.svg)](https://github.com/reslaid/cert-thief.git) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/59f8c24c9440417782b450854839c284)](https://app.codacy.com/gh/reslaid/cert-thief/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade) <img src="https://skillicons.dev/icons?i=rust" alt="Language: Rust" style="width:20px;height:20px;"> [![Commit activity](https://img.shields.io/github/commit-activity/m/reslaid/cert-thief)](https://github.com/reslaid/cert-thief/commits) [![Last Commit](https://img.shields.io/github/last-commit/reslaid/cert-thief/main)](https://github.com/reslaid/cert-thief/commits)
> [![GitHub release](https://img.shields.io/github/release/reslaid/cert-thief.svg)](https://github.com/reslaid/cert-thief/releases) [![GitHub release date](https://img.shields.io/github/release-date/reslaid/cert-thief?color=blue)](https://github.com/reslaid/cert-thief/releases) [![License](https://img.shields.io/badge/license-GPL%203.0-blue.svg)](https://github.com/reslaid/cert-thief/blob/main/LICENSE) [![Platform Badge](https://img.shields.io/badge/Windows-0078D6?logo=windows)](https://github.com/reslaid/cert-thief)

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

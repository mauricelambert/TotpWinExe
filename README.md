![TotpApp Logo](https://mauricelambert.github.io/info/python/security/TotpApp_small.png "TotpApp logo")

# TotpWinExe

## Description

Little GUI Windows application to enter a secret key and obtain your TOTP without any phone or other device.

## Requirements

 - No requirements

## Download

 - https://github.com/mauricelambert/TotpWinExe/releases

## Compilation

```bash
nim --app:gui c --stackTrace:off  --lineTrace:off --checks:off --assertions:off -d:release -d=mingw --opt:size --passl:"-s" TotpWinExe.nim
```

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).

# vless-clean

Automatically filters the upstream VLESS subscription and removes entries using unsafe certificate-verification settings.

Filtered parameters:
- allowInsecure=1/true/yes/on
- insecure=1/true/yes/on
- fp=unsafe

The generated subscription is in `sub.txt` and is refreshed hourly by GitHub Actions.

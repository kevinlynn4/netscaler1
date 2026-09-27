# NetScaler Compromise Triage

A fast, local, read-mostly IOC/post-compromise checker intended to run directly from the
Citrix NetScaler ADC / Gateway shell.

It is deliberately **not** an exploit or remote vulnerability scanner.

## Requirements

The script uses `/bin/sh` and ordinary utilities available on NetScaler appliances:
`hostname`, `date`, `uname`, `find`, `ls`, `file`, `grep`, `ps`, and shell built-ins.

No Python packages, pip, jq, package installation, or remote API is required.

## Run

Log in as `nsroot`, then:

```text
> shell
# /bin/sh ./netscaler_compromise_triage.sh
```

Exit codes:

- `0` — no indicators found by these checks
- `1` — suspicious/hunt findings found
- `2` — high-confidence compromise indicator(s) found

## What it checks

- Documented NetScaler webshell/backdoor paths
- SUID shells under temporary directories
- Unexpected PHP/XHTML files in NetScaler web paths
- Recently modified script-like web files
- High-signal webshell content strings
- `rc.netscaler` persistence
- cron persistence, including the `nobody` cron mechanism observed by Mandiant
- suspicious processes executing from temporary directories
- NetScaler HTTPD configuration tampering
- shell-history post-exploitation commands
- NSPPE core dumps (low-confidence / preserve for forensics)
- HTTP access logs for documented webshell paths

## Important

A clean result does not prove the appliance is uncompromised.

If high-confidence compromise indicators are found, preserve evidence when feasible,
isolate the appliance, rebuild it, rotate all secrets/certificates/private keys exposed
to it, and investigate systems it could reach.

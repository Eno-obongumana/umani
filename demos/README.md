# UMANI demos

Every module has a reproducible demo. Targets run on 127.0.0.1 only.

## Run all

```bash
bash demos/run-all.sh

## Demo matrix

| Module        | Demo                   | Target        | Proves                            |
|---------------|------------------------|---------------|-----------------------------------|
| headers       | test_headers.py        | simple_flask  | Detects missing CSP, HSTS         |
| cors          | test_cors.py           | simple_flask  | Detects origin reflection + creds |
| open_redirect | test_open_redirect.py  | simple_flask  | Detects open redirect             |
| xss           | test_xss.py            | simple_flask  | Detects reflected XSS             |
| sqli          | test_sqli.py           | simple_flask  | Detects SQL injection             |
| dir_brute     | test_dir_brute.py      | simple_flask  | Discovers hidden paths            |
| spider        | test_spider.py         | simple_flask  | Crawls links and forms            |
| csrf          | test_csrf.py           | simple_flask  | Finds unprotected POST forms      |
| intruder      | test_intruder.py       | simple_flask  | Fuzzes params, flags anomalies    |
| (repeater)    | test_repeater.py       | simple_flask  | Replays findings with overrides   |
| ssrf          | test_ssrf.py           | simple_flask  | Detects SSRF via canary callback  |
| xxe           | test_xxe.py            | simple_flask  | Detects XXE file disclosure + SSRF|
| (proxy)       | test_proxy.py          | simple_flask  | Logs proxied HTTP traffic         |
| log4shell     | test_log4shell.py      | simple_flask  | Detects Log4Shell via canary      |
| (passive)     | test_passive_scan.py   | simple_flask  | Proxy auto-scans every response   |

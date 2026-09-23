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

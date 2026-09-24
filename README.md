# UMANI

A modular web security testing framework.

**For authorized testing only. See ETHICS.md.**

## Install

```bash
git clone <your-repo> && cd umani
python3 -m venv venv && source venv/bin/activate
pip install -e .
pip install flask

## Docker

Run UMANI without installing Python:

```bash
# Build once
docker build -t umani .

# List modules
docker run --rm umani modules

# Scan a target (use host network to reach localhost)
docker run --rm --network host umani scan http://127.0.0.1:5000/

# Start the proxy
docker run --rm --network host -p 8080:8080 umani proxy --port 8080

# Persist state (DB, CA) across runs
docker run --rm -v umani-data:/data umani scan http://127.0.0.1:5000/

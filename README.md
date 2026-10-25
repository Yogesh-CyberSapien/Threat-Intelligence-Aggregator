[Uploading README.md…]()
# Threat Intelligence Aggregator

A Python CLI tool that pulls **live Indicators of Compromise (IoCs)** from the **VirusTotal v3** and **AlienVault OTX v1** APIs, merges and deduplicates them, and renders a colour-coded threat report.

---

## Features

| Feature | Detail |
|---|---|
| **Multi-source** | VirusTotal v3 + AlienVault OTX v1 |
| **IoC types** | IP, Domain, URL, File hash (MD5/SHA-1/SHA-256) |
| **Pulse extraction** | Pull IoCs directly from your OTX subscribed pulses |
| **Deduplication** | Same IoC from two sources → merged record with combined vote counts |
| **Threat scoring** | 0–100 normalised score; HIGH ≥ 60, MEDIUM ≥ 25, LOW > 0 |
| **Output formats** | Colour table, JSON, CSV, Summary |
| **File export** | `--output report.csv` writes ANSI-stripped output to disk |

---

## Quick Start

```bash
# 1. Clone / enter the project directory
cd threat-intel-aggregator

# 2. Create a virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys
copy .env.example .env          # Windows
# cp .env.example .env          # macOS / Linux
# → Edit .env and fill in both keys
```

---

## API Keys

| Service | Where to get it |
|---|---|
| VirusTotal | https://www.virustotal.com/gui/my-apikey (free tier: 4 req/min) |
| AlienVault OTX | https://otx.alienvault.com/api (free) |

---

## Usage

```
python main.py --help
```

### Query an IP from both sources (default)
```bash
python main.py --type ip --values 185.220.101.34
```

### Query multiple domains, output JSON
```bash
python main.py --type domain --values evil.com bad-actor.net --format json
```

### Query a file hash, save CSV
```bash
python main.py --type hash \
  --values d41d8cd98f00b204e9800998ecf8427e \
  --format csv --output hashes.csv
```

### Pull the 10 latest OTX pulses
```bash
python main.py --pulses --limit 10
```

### Use only VirusTotal
```bash
python main.py --type ip --values 1.2.3.4 --sources virustotal
```

### Only show HIGH severity results
```bash
python main.py --type domain --values evil.com --min-score 60
```

---

## CLI Reference

| Flag | Description |
|---|---|
| `--type` / `-t` | IoC type: `ip`, `domain`, `url`, `hash` |
| `--values` / `-v` | One or more indicator values |
| `--pulses` | Fetch IoCs from latest subscribed OTX pulses |
| `--limit` / `-l` | Number of pulses to fetch (default: 5) |
| `--sources` / `-s` | `virustotal`, `alienvault`, or both (default) |
| `--format` / `-f` | `table` (default), `json`, `csv`, `summary` |
| `--output` / `-o` | Write output to a file |
| `--min-score` | Filter out IoCs below this threat score |
| `--no-colour` | Disable ANSI colours |
| `--verbose` / `-V` | Enable DEBUG logging |

---

## Project Structure

```
threat-intel-aggregator/
├── main.py                  # CLI entry point
├── config.py                # API keys + constants
├── models.py                # IoC dataclass
├── virustotal_client.py     # VirusTotal API v3 client
├── alienvault_client.py     # AlienVault OTX API v1 client
├── aggregator.py            # Merge / deduplicate / score
├── formatters.py            # Table / JSON / CSV / summary output
├── tests/
│   ├── test_aggregator.py
│   ├── test_virustotal_client.py
│   └── test_alienvault_client.py
├── requirements.txt
├── .env.example
└── README.md
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

Tests use `unittest.mock` to patch HTTP calls — no live API keys required.

# The_Collector - a Sentinel Crawler
###### Enhanced Blue/Red Team Scraper
alpha release

Sentinel is an advanced web crawler for OSINT and red team operations. It collects target site information, detects keywords, and stores results in a SQLite database. Built for both normal reconnaissance and stealthy Tor-based operations.

## Features

- Multi-threaded crawling with configurable depth and concurrency
- Duplicate content detection via MD5 hashing
- Keyword detection with context snippets
- Language detection (optional, via `langdetect`)
- SQLite database storage for structured results
- Optional Tor integration for anonymous crawling
- Configurable delay between requests to respect targets

## Installation

Optional dependencies for stealth mode:

```bash
pip install pysocks langdetect
```

Make sure Tor service or Tor Browser is running for `.onion` crawling.

## Usage

### 1. Normal Mode (OSINT / Info Gathering)

Collects information about a target website and stores results in the database.

```bash
python sentinel_crawler.py --url "https://target-company.com" --keywords "confidential" "password" "admin" --db target_scan.db
```

### 2. Darkweb / Stealth Mode (Red Team)

For scanning `.onion` addresses or hiding your IP. Make sure Tor is running on port 9050.

```bash
python sentinel_crawler.py --url "http://exampleonionaddress.onion" --keywords "leak" "database" --tor --delay 2.0
```

### 3. Data Analysis

Since results are stored in SQLite, you can filter and analyze data easily. Use a tool like [DB Browser for SQLite](https://sqlitebrowser.org/) or a quick Python script:

```python
import sqlite3

# Quick Check Script
conn = sqlite3.connect('sentinel_results.db')
cursor = conn.cursor()
cursor.execute("SELECT url, context FROM hits WHERE keyword='password'")
for row in cursor.fetchall():
    print(f"Found at: {row[0]}\nContext: {row[1]}\n---")
```

## Configuration

* `--depth`: Maximum crawl depth (default: 2)
* `--max`: Maximum pages to crawl (default: 100)
* `--delay`: Delay between requests in seconds (default: 1.0)
* `--threads`: Number of concurrent threads (default: 5)
* `--tor`: Enable Tor proxy (127.0.0.1:9050)
* `--db`: SQLite database filename

## Example

```bash
python sentinel_crawler.py --url "https://target.com" --keywords "admin" "confidential" --depth 3 --threads 10 --db scan_results.db
```

## Credits

* **The_Collector** - Sentinel Crawler - Enhanced Blue/Red Team Scraper
* Based on concepts by The Collector (PRO)

## Disclaimer

Use this tool responsibly. Only scan targets you are authorized to analyze. Misuse may be illegal and can have serious consequences.



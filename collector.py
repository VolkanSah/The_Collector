# ==================================================================
# PROJECT: The_Collector - Sentinel Crawler / Blue & Red Team Toolkit
# AUTHOR:  Volkan Sah (Kücükbudak)
# YEARS:   2008-2025
#
# LICENSE: GNU General Public License v3 (GPLv3)
# ------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for details.
#
# A copy of the GPLv3 must accompany this distribution.
#
# --- MANDATORY GPLv3 REQUIREMENTS ---------------------------------
# 1. You MUST retain this copyright notice. This code is free, NOT
#    Public Domain. Removing the author line violates the GPLv3 and
#    immediately terminates your rights to use this code.
#
# 2. If you modify and distribute this code, your version MUST also
#    be licensed under the GPLv3 — and you MUST release the source.
#
# Respect open-source developers. Do not remove or obscure authorship.
# ------------------------------------------------------------------
# T H I N K   B E F O R E   Y O U   T Y P E !
# ==================================================================
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
import argparse
import logging
import json
import sqlite3
import hashlib
import sys
import socket
from typing import Set, List, Dict, Optional

# Optional imports
try:
    import socks
    TOR_AVAILABLE = True
except ImportError:
    TOR_AVAILABLE = False

try:
    from langdetect import detect
    LANG_AVAILABLE = True
except ImportError:
    LANG_AVAILABLE = False

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("Sentinel")

# Suppress insecure request warnings for self-signed certificates
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class DatabaseManager:
    """Handles SQLite operations safely."""
    def __init__(self, db_name="sentinel_data.db"):
        self.db_name = db_name
        self.init_db()

    def init_db(self):
        """Create tables for pages and hits if they don't exist."""
        with sqlite3.connect(self.db_name) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS pages
                         (url TEXT PRIMARY KEY, 
                          status INT, 
                          title TEXT,
                          language TEXT, 
                          content_hash TEXT, 
                          timestamp REAL,
                          has_keywords BOOLEAN)''')
            c.execute('''CREATE TABLE IF NOT EXISTS hits
                         (url TEXT, 
                          keyword TEXT, 
                          context TEXT,
                          timestamp REAL)''')
            conn.commit()

    def save_page(self, data: Dict):
        """Save page and its keyword hits to DB."""
        try:
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                c.execute('''INSERT OR REPLACE INTO pages 
                             (url, status, title, language, content_hash, timestamp, has_keywords)
                             VALUES (?, ?, ?, ?, ?, ?, ?)''',
                          (data['url'], data['status'], data['title'], 
                           data['language'], data['content_hash'], time.time(), data['is_hit']))
                
                if data['hits']:
                    for hit in data['hits']:
                        c.execute('INSERT INTO hits (url, keyword, context, timestamp) VALUES (?, ?, ?, ?)',
                                  (data['url'], hit['keyword'], hit['context'], time.time()))
                conn.commit()
        except Exception as e:
            logger.error(f"Database error: {e}")

    def get_visited_hashes(self) -> Set[str]:
        """Load content hashes to skip duplicate content on different URLs."""
        with sqlite3.connect(self.db_name) as conn:
            c = conn.cursor()
            c.execute("SELECT content_hash FROM pages")
            return {row[0] for row in c.fetchall()}


class SecurityCrawler:
    """Main crawler class."""
    def __init__(self, start_url: str, keywords: List[str], config: Dict):
        self.start_url = start_url
        self.keywords = [k.lower() for k in keywords]
        self.config = config
        
        # State
        self.visited_links: Set[str] = set()
        self.visited_hashes: Set[str] = set()
        self.domain = urlparse(start_url).netloc
        self.hits_count = 0
        
        # Components
        self.db = DatabaseManager(config.get('db_name', 'sentinel_data.db'))
        self.visited_hashes = self.db.get_visited_hashes()
        
        # Networking session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.get('user_agent', 'Sentinel/2.0 (Security Audit)'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        self.last_request_time = 0

    def _setup_tor(self):
        """Configure Tor proxy if requested."""
        if not TOR_AVAILABLE:
            logger.error("PySocks not installed. Cannot use Tor. Run: pip install pysocks")
            sys.exit(1)
        
        tor_port = 9050
        # Check if Tor is running
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", tor_port))
            s.close()
        except Exception:
            logger.error(f"Tor service not reachable on 127.0.0.1:{tor_port}. Is Tor running?")
            sys.exit(1)

        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", tor_port)
        socket.socket = socks.socksocket
        logger.info("Tor proxy enabled.")

    def _respect_delay(self):
        """Enforce crawling delay to avoid overwhelming servers."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.config['delay']:
            time.sleep(self.config['delay'] - elapsed)
        self.last_request_time = time.time()

    def normalize_url(self, url: str, base_url: str) -> Optional[str]:
        """Normalize and validate URLs for scope and deduplication."""
        if url.startswith(('mailto:', 'tel:', 'javascript:', '#', 'data:')):
            return None
        try:
            if not url.startswith(('http://', 'https://')):
                url = urljoin(base_url, url)
            parsed = urlparse(url)
            normalized = parsed._replace(fragment='', query='').geturl()
            if self.domain and parsed.netloc != self.domain:
                return None
            return normalized
        except Exception:
            return None

    def analyze_content(self, text: str, url: str) -> Dict:
        """Language detection, hashing, and keyword search."""
        content_hash = hashlib.md5(text.encode('utf-8', errors='ignore')).hexdigest()
        lang = "unknown"
        if LANG_AVAILABLE and len(text) > 50:
            try:
                lang = detect(text[:1000])
            except:
                pass
        hits = []
        lower_text = text.lower()
        is_hit = False
        for keyword in self.keywords:
            if keyword in lower_text:
                is_hit = True
                idx = lower_text.find(keyword)
                start = max(0, idx - 30)
                end = min(len(text), idx + len(keyword) + 30)
                context = text[start:end].replace('\n', ' ').strip()
                hits.append({'keyword': keyword, 'context': f"...{context}..."})
        return {
            'hash': content_hash,
            'language': lang,
            'is_hit': is_hit,
            'hits': hits
        }

    def crawl_page(self, url: str) -> Dict:
        """Crawl a single page and extract links and relevant info."""
        try:
            self._respect_delay()
            response = self.session.get(url, timeout=15, verify=False, stream=False)
            if 'text/html' not in response.headers.get('content-type', '').lower():
                return {'url': url, 'links': set(), 'status': response.status_code, 'skip': True}

            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Remove scripts, styles, nav, footer, iframe
            for tag in soup(["script", "style", "nav", "footer", "iframe"]):
                tag.decompose()
            
            text = soup.get_text(separator=' ', strip=True)
            title = soup.title.string if soup.title else "No Title"
            
            analysis = self.analyze_content(text, url)
            
            if analysis['hash'] in self.visited_hashes:
                logger.debug(f"Skipping duplicate content: {url}")
                return {'url': url, 'links': set(), 'status': response.status_code, 'skip': True}
            
            self.visited_hashes.add(analysis['hash'])
            if analysis['is_hit']:
                logger.warning(f"MATCH found on {url} (Lang: {analysis['language']})")
                self.hits_count += 1
            
            links = set()
            for link in soup.find_all('a', href=True):
                norm = self.normalize_url(link['href'], url)
                if norm:
                    links.add(norm)
            
            result = {
                'url': url,
                'status': response.status_code,
                'title': title,
                'language': analysis['language'],
                'content_hash': analysis['hash'],
                'is_hit': analysis['is_hit'],
                'hits': analysis['hits'],
                'links': links,
                'skip': False
            }
            self.db.save_page(result)
            return result

        except requests.RequestException as e:
            logger.error(f"Connection error {url}: {str(e)[:50]}")
            return {'url': url, 'links': set(), 'error': str(e), 'skip': True}
        except Exception as e:
            logger.error(f"Processing error {url}: {str(e)}")
            return {'url': url, 'links': set(), 'error': str(e), 'skip': True}

    def start(self):
        """Main crawling loop using ThreadPoolExecutor."""
        if self.config.get('use_tor'):
            self._setup_tor()
            
        queue = deque([(self.start_url, 0)])
        self.visited_links.add(self.start_url)
        crawled_count = 0
        
        logger.info(f"Initializing Sentinel Crawler target: {self.start_url}")
        logger.info(f"Searching for: {self.keywords}")
        
        workers = self.config.get('threads', 5)
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            while queue and crawled_count < self.config['max_pages']:
                batch_futures = {}
                while queue and len(batch_futures) < workers * 2:
                    url, depth = queue.popleft()
                    if depth <= self.config['depth']:
                        future = executor.submit(self.crawl_page, url)
                        batch_futures[future] = (url, depth)
                
                if not batch_futures:
                    break
                
                for future in as_completed(batch_futures):
                    url, depth = batch_futures[future]
                    try:
                        res = future.result()
                        crawled_count += 1
                        if not res.get('skip', False):
                            logger.info(f"Processed [{crawled_count}] Depth:{depth} Code:{res.get('status')} URL:{url}")
                            if depth < self.config['depth']:
                                for link in res.get('links', set()):
                                    if link not in self.visited_links:
                                        self.visited_links.add(link)
                                        queue.append((link, depth + 1))
                    except Exception as e:
                        logger.error(f"Critical Worker Error: {e}")

        self._print_summary(crawled_count)

    def _print_summary(self, count):
        """Print a crawl summary with top matches."""
        print("\n" + "="*60)
        print(f"CRAWL FINISHED - {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        print(f"Pages Scanned:   {count}")
        print(f"Relevant Hits:   {self.hits_count}")
        print(f"Unique Hashes:   {len(self.visited_hashes)}")
        print(f"Database:        {self.db.db_name}")
        print("="*60)
        
        if self.hits_count > 0:
            print("\nTop Matches (Check DB for details):")
            with sqlite3.connect(self.db.db_name) as conn:
                c = conn.cursor()
                for row in c.execute("SELECT url, keyword FROM hits LIMIT 5"):
                    print(f"Found '{row[1]}' on: {row[0]}")
        print("\n")


def main():
    parser = argparse.ArgumentParser(description='Sentinel: Advanced Blue/Red Team Crawler')
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--keywords', nargs='+', required=True, help='Keywords (space separated)')
    parser.add_argument('--depth', type=int, default=2, help='Crawl depth')
    parser.add_argument('--max', type=int, default=100, dest='max_pages', help='Max pages')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay (sec)')
    parser.add_argument('--threads', type=int, default=5, help='Concurrent threads')
    parser.add_argument('--tor', action='store_true', help='Route via Tor (127.0.0.1:9050)')
    parser.add_argument('--db', default='sentinel_results.db', help='Output DB filename')
    
    args = parser.parse_args()
    
    config = {
        'depth': args.depth,
        'max_pages': args.max_pages,
        'delay': args.delay,
        'threads': args.threads,
        'use_tor': args.tor,
        'db_name': args.db
    }
    
    crawler = SecurityCrawler(args.url, args.keywords, config)
    
    try:
        crawler.start()
    except KeyboardInterrupt:
        logger.warning("Interrupted manually. Data is safe in SQLite.")


if __name__ == "__main__":
    main()

import asyncio
import aiohttp
from bs4 import BeautifulSoup
import json
import sys
import re
import random
from fake_useragent import UserAgent

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

def get_random_ua():
    try:
        return UserAgent(fallback=DEFAULT_USER_AGENTS[0]).random
    except Exception:
        return random.choice(DEFAULT_USER_AGENTS)

if len(sys.argv) < 2:
    print("[-] Masukin targetnya, tolol! Contoh: python dark_crawler.py aditya")
    sys.exit(1)

# Gabungin argumen kalau lebih dari satu kata (misal nama lengkap)
TARGET = " ".join(sys.argv[1:])

async def fetch(session, url):
    try:
        async with session.get(url, headers={"User-Agent": get_random_ua()}, timeout=10) as response:
            if response.status == 200:
                return await response.text()
    except Exception as e:
        pass
    return None

def extract_sensitive_data(raw_text):
    emails = list(set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', raw_text)))
    phones = list(set(re.findall(r'\+?[0-9][0-9()\-\s]{7,20}[0-9]', raw_text)))
    return {
        "emails": emails,
        "phones": phones
    }

async def scrape_github(session, query):
    formatted_query = query.replace(" ", "+")
    url = f"https://github.com/search?q={formatted_query}&type=users"
    html = await fetch(session, url)
    results = []
    raw_html_dump = ""
    if html:
        raw_html_dump += html
        soup = BeautifulSoup(html, 'html.parser')
        for user in soup.select('.user-list-item, .f4 a'):
            results.append(user.text.strip())
    
    extracted = extract_sensitive_data(raw_html_dump)
    return {
        "source": "GitHub",
        "users_found": list(set(results)),
        "extracted_data": extracted
    }

async def scrape_duckduckgo(session, query):
    formatted_query = query.replace(" ", "+")
    url = f"https://html.duckduckgo.com/html/?q={formatted_query}"
    html = await fetch(session, url)
    results = []
    raw_html_dump = ""
    if html:
        raw_html_dump += html
        soup = BeautifulSoup(html, 'html.parser')
        for a in soup.select('.result__url'):
            results.append(a.text.strip())
            
    extracted = extract_sensitive_data(raw_html_dump)
    return {
        "source": "DuckDuckGo Web Index",
        "links_found": list(set(results)),
        "extracted_data": extracted
    }

async def main():
    print(f"[*] Ngamuk narik data buat target: '{TARGET}'...")
    async with aiohttp.ClientSession() as session:
        tasks = [
            scrape_github(session, TARGET),
            scrape_duckduckgo(session, TARGET)
        ]
        
        responses = await asyncio.gather(*tasks)
        
        output = {
            "target": TARGET,
            "status": "Success",
            "results": responses
        }
        
        filename = f"{TARGET.replace(' ', '_')}_scan.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4, ensure_ascii=False)
            
        print(f"[+] Beres, bajingan! Hasil kesimpen bersih di {filename}")

if __name__ == "__main__":
    asyncio.run(main())
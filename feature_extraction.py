import re
import urllib.parse
from bs4 import BeautifulSoup
import httpx
import asyncio
import socket
import math
from app.utils.logger import logger
import tldextract

def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

async def get_geolocation(ip_address):
    # Uses free ip-api (rate limited, but no key required)
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip_address}")
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown")
                }
    except Exception as e:
        logger.warning(f"Geolocation lookup failed: {e}")
    return {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "org": "Unknown"}

async def extract_features_async(url):
    """
    Extracts ML features AND forensic intelligence concurrently.
    """
    if not url.startswith('http'):
        url = 'http://' + url
        
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc
    
    # 1. Base ML Features
    features = {
        'having_ip_address': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
        'url_length': 1 if len(url) > 54 else 0,
        'having_at_symbol': 1 if '@' in url else 0,
        'prefix_suffix_dash': 1 if '-' in domain else 0,
        'multi_subdomains': 1 if domain.count('.') > 2 else 0,
        'https_token': 1 if 'https' in domain else 0,
        'has_https': 1 if parsed_url.scheme == 'https' else 0,
        'shortining_service': 1 if re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url) else 0,
        'count_dots': url.count('.'),
        'count_digits': sum(c.isdigit() for c in url),
        'count_special_chars': sum(not c.isalnum() for c in url),
        'has_suspicious_words': 1 if re.search(r'secure|account|webscr|login|ebayisapi|signin|banking|confirm', url.lower()) else 0,
        'domain_age': 1, # Mocked for speed
        'favicon_mismatch': 0,
        'redirects': 0,
        'has_hidden_iframes': 0,
        'has_password_fields': 0
    }

    # 2. Forensic Intelligence Object
    intelligence = {
        "network": {
            "ip_address": "Unknown",
            "domain": domain,
            "geolocation": {}
        },
        "http": {
            "status_code": None,
            "server": "Unknown",
            "headers": {},
            "is_https": parsed_url.scheme == 'https',
            "response_time_ms": 0
        },
        "content": {
            "title": "None",
            "script_tags": 0,
            "external_links": 0,
            "internal_links": 0
        },
        "lexical": {
            "entropy": round(calculate_entropy(url), 2),
            "length": len(url)
        }
    }

    # Extract Domain / IP
    try:
        ip = socket.gethostbyname(domain.split(':')[0])
        intelligence["network"]["ip_address"] = ip
        intelligence["network"]["geolocation"] = await get_geolocation(ip)
    except Exception as e:
        logger.warning(f"DNS Resolution failed for {domain}: {e}")

    # Fetch Live HTML (Async)
    try:
        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
            
            intelligence["http"]["status_code"] = resp.status_code
            intelligence["http"]["server"] = resp.headers.get("Server", "Unknown")
            intelligence["http"]["headers"] = dict(resp.headers)
            intelligence["http"]["response_time_ms"] = int(resp.elapsed.total_seconds() * 1000)

            if len(resp.history) > 0:
                features['redirects'] = 1
                
            html = resp.text
            soup = BeautifulSoup(html, 'html.parser')
            
            # Extract ML DOM Features
            if soup.find_all('iframe', style=lambda value: value and ('visibility:hidden' in value.replace(' ', '') or 'display:none' in value.replace(' ', ''))):
                features['has_hidden_iframes'] = 1
                
            if soup.find_all('input', type='password'):
                features['has_password_fields'] = 1

            # Extract Forensic DOM Features
            title_tag = soup.find('title')
            intelligence["content"]["title"] = title_tag.text.strip() if title_tag else "No Title Found"
            intelligence["content"]["script_tags"] = len(soup.find_all('script'))
            
            ext_tld = tldextract.extract(url)
            base_domain = f"{ext_tld.domain}.{ext_tld.suffix}"
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if href.startswith('http') and base_domain not in href:
                    intelligence["content"]["external_links"] += 1
                else:
                    intelligence["content"]["internal_links"] += 1
                    
    except httpx.RequestError as exc:
        logger.warning(f"Failed to fetch live HTML for {url}: {exc}")
        intelligence["http"]["status_code"] = "Failed to connect"

    return features, intelligence

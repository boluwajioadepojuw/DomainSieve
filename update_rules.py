import requests
from datetime import datetime
from base64 import b64encode
import hashlib
import sys
import json
import os
import re
import unicodedata
from nrd_processor import process_nrd_list

phishstats_url = "https://api.phishstats.info/api/phishing?_sort=-id"
openphish_url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
index_json_url = os.environ.get("PHISHBARRIER_INDEX_URL", "")
output_file = "phishbarrier.rules"
phishing_list = "phishing.lst"
sid_file = "sid_tracker.txt"
index_file = "index.json"

banner = """\033[32m
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠃⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⡿⠿⠛⢉⣀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⠟⢁⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⠃⣰⣿\033[41;37m PHISHBARRIER \033[0;32m⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⠀⢿⣿⣿⣿⣿⣿⡏⠀⢠⣾⣿⣿⡆⠀⠸⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿
⣿⣧⠈⠻⣿⣿⣿⣿⣷⠾⠻⣿⣿⣿⠇⠀⢰⣿⣿⣿⣿⣿⣷⠀⠙⢿⣿⣿⣿⣿
⣿⣿⣿⣦⣄⣈⣉⣀⣤⣴⡞⠋⠉⠁⠀⠠⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠻⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣦⠀⠀⠘⣿⣿⣿⣿⣿⣿⡇⠀⡀⠀⠹⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠈⢿⣿⣿⣿⣿⣧⣾⣿⡄⠀⢹⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠈⢿⣿⣿⣿⣿⣿⣿⠇⠀⢸⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠻⢿⣿⣿⡿⠋⠀⠀⣼⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣤⣤⣶⣾⣿⣿⣿⣿
SID range: 6000000-6100000 ⣿⣿⣿
\033[0m
https://github.com/boluwaji/DomainSieve
"""

def fetch_phishing_urls(url):
    response = requests.get(url, timeout=(15, 60))  # connect + read timeouts: never hang on a dead feed
    if response.status_code == 200:
        if "phishstats" in url:
            data = response.json()
            return [item.get('url') for item in data if item.get('url')]
        else:
            return response.text.splitlines()
    else:
        raise Exception(f"Failed to fetch data: {response.status_code}")

def get_last_sid():
    try:
        with open(sid_file, "r") as f:
            return int(f.read().strip())
    except FileNotFoundError:
        return 6000002  # SIDs 6000000 (DNS) and 6000001 (TLS) are reserved fixed rules
    except ValueError:
        return 6000002

def is_domain_in_rules(domain, rules):
    # Check whether the domain already exists in the HTTP rules
    for rule in rules:
        if 'content:"' + domain + '"' in rule:
            return True
    return False

def is_domain_in_phishing_list(domain):
    try:
        with open(phishing_list, "r") as f:
            domains = f.readlines()
            encoded_domain = b64encode(domain.encode()).decode()
            return encoded_domain + "\n" in domains
    except FileNotFoundError:
        return False

def update_dataset(domain, rules):
    # Check whether the domain is already in the rules or the list
    if not is_domain_in_rules(domain, rules) and not is_domain_in_phishing_list(domain):
        with open(phishing_list, "a") as f:
            encoded_domain = b64encode(domain.encode()).decode()
            f.write(encoded_domain + "\n")

def create_suricata_rules(urls, reference, last_sid, existing_rules):
    rules = []
    sid = last_sid
    urls = list(set(urls))
    total = len(urls)
    
    for i, url in enumerate(urls, 1):
        rule = ""

        if url:
            print(f"\r\033[K[{i}/{total}] Processing {reference}: {url[:60]}", end="")
            current_data = datetime.now().strftime("%Y_%m_%d")
            
            if "://" in url:
                phish_url = url.split("://", 1)[1]
            else:
                phish_url = url

            new_phish_url = phish_url.replace('.',' .')
            new_phish_url = phish_url.replace(';','\\;')

            if "/" not in phish_url:
                # Domain-only entries go on the phishing domain list
                domain = phish_url
                if not is_domain_in_rules(domain, existing_rules):
                    update_dataset(domain, existing_rules)
            else:
                domain = phish_url.split('/')[0]
                path = phish_url.split(domain, 1)[1]
                # Neutralize characters that could break out of the Suricata
                # content:"..." token (quote), its escaping (backslash), or the
                # line-oriented rules file (control characters).
                path = path.replace('|', '|7c|').replace(';', '|3b|').replace('"', '|22|').replace('\\', '|5c|')
                domain = domain.replace('|', '|7c|').replace(';', '|3b|').replace('"', '|22|').replace('\\', '|5c|')
                msg_domain = new_phish_url.replace('|', '|7c|').replace(';', '|3b|').replace('"', '|22|').replace('\\', '|5c|')
                path = ''.join(c for c in path if unicodedata.category(c)[0] != 'C')
                domain = ''.join(c for c in domain if unicodedata.category(c)[0] != 'C')
                msg_domain = ''.join(c for c in msg_domain if unicodedata.category(c)[0] != 'C')

                # Check whether the domain/path already exists in the rules
                if not is_domain_in_rules(domain, existing_rules):
                    rule = f'alert http $HOME_NET any -> any any (msg:"DomainSieve related malicious URL ({msg_domain})"; flow:established,to_server; http.uri; content:"{path}"; startswith; fast_pattern; http.host; content:"{domain.lower()}"; endswith; reference:url,{reference}; reference:url,/AT/signature.html?sid={sid}; classtype:social-engineering; sid:{sid}; rev:1; metadata: signature_severity Major, created_et {current_data};)\n'
                    sid += 1

            if rule:
                rules.append(rule)
                
    print()  # Break the line after the loop
    return rules, sid

def update_from_index():
    print(banner)
    if not index_json_url:
        raise Exception(
            "No index.json source configured. Set the index URL in the "
            "index_json_url variable (or env PHISHBARRIER_INDEX_URL) before "
            "using --update."
        )
    print(f"\nFetching index.json from {index_json_url}...")
    response = requests.get(index_json_url, timeout=(15, 60))
    if response.status_code == 200:
        with open(index_file, "w") as f:
            f.write(response.text)
    else:
        raise Exception(f"Failed to fetch index: {response.status_code}")

    with open(index_file, "r") as f:
        data = json.load(f)

    try:
        with open(output_file, "r") as f:
            existing_rules = f.readlines()
    except FileNotFoundError:
        existing_rules = []

    rules_by_sid = {}
    rules_by_msg = {}
    for rule in existing_rules:
        if not rule.startswith("alert http"):
            continue
        m_sid = re.search(r"sid:(\d+);", rule)
        if m_sid:
            rules_by_sid[int(m_sid.group(1))] = rule
        m_msg = re.search(r'msg:"([^"]+)";', rule)
        if m_msg:
            rules_by_msg[m_msg.group(1)] = rule

    active_items = [item for item in data if item.get("rule_status") == "active" and item.get("protocol") == "http"]
    total = len(active_items)

    rules = []
    sid = 6000002
    seen_hosts = {}   # host -> primeiro SID que o registrou
    duplicates_skipped = 0

    for i, item in enumerate(active_items, 1):
        item_sid = item.get("sid")
        msg = item.get("name", "")
        print(f"\r\033[K[{i}/{total}] Processing active rule: {msg[:60]}", end="")

        rule_str = rules_by_sid.get(item_sid) or rules_by_msg.get(msg)
        if rule_str:
            rule_str = re.sub(r"sid:\d+;", f"sid:{sid};", rule_str)
            rule_str = re.sub(r"signature\.html\?sid=\d+", f"signature.html?sid={sid}", rule_str)
        else:
            m = re.match(r"^DomainSieve related malicious URL \((.*)\)$", msg)
            if m:
                new_phish_url = m.group(1)
                phish_url = new_phish_url.replace(" .", ".").replace(r"\;", ";")
                if "/" in phish_url:
                    domain = phish_url.split("/")[0]
                    path = phish_url.split(domain, 1)[1]
                else:
                    domain = phish_url
                    path = "/"
                # Neutralize rule-token breakout characters, same as the
                # live-feed path (quote -> |22|, backslash -> |5c|, ; -> |3b|),
                # plus control characters that would corrupt the rules file.
                path = path.replace('|', '|7c|').replace(';', '|3b|').replace('"', '|22|').replace('\\', '|5c|')
                domain = domain.replace('|', '|7c|').replace(';', '|3b|').replace('"', '|22|').replace('\\', '|5c|')
                msg_domain = new_phish_url.replace('|', '|7c|').replace(';', '|3b|').replace('"', '|22|').replace('\\', '|5c|')
                path = ''.join(c for c in path if unicodedata.category(c)[0] != 'C')
                domain = ''.join(c for c in domain if unicodedata.category(c)[0] != 'C')
                msg_domain = ''.join(c for c in msg_domain if unicodedata.category(c)[0] != 'C')
                current_data = datetime.now().strftime("%Y_%m_%d")
                rule_str = f'alert http $HOME_NET any -> any any (msg:"DomainSieve related malicious URL ({msg_domain})"; flow:established,to_server; http.uri; content:"{path}"; startswith; fast_pattern; http.host; content:"{domain.lower()}"; endswith; reference:url,phishstats.info; reference:url,/AT/signature.html?sid={sid}; classtype:social-engineering; sid:{sid}; rev:1; metadata: signature_severity Major, created_et {current_data};)\n'
            else:
                continue

        # --- dedupe by http.host ---
        m_host = re.search(r'http\.host; content:"([^"]+)"', rule_str)
        if m_host:
            host = m_host.group(1).lower()
            if host in seen_hosts:
                duplicates_skipped += 1
                print(f"\r\033[K  [SKIP] Duplicate host '{host}' (already mapped to SID {seen_hosts[host]}, current item SID {item_sid})")
                continue
            seen_hosts[host] = sid
        # ----------------------------------

        rules.append(rule_str)
        sid += 1

    print()
    if duplicates_skipped:
        print(f"Deduplication: {duplicates_skipped} rule(s) removed (same http.host already present).")

    domain_rule = 'alert dns $HOME_NET any -> any any (msg:"LureBarrier DNS query to suspicious domain - Phishing"; dns.query; dataset:isset,phishing_domains,type string; reference:url,https://github.com/boluwaji/DomainSieve; classtype:social-engineering; sid:6000000; rev:1; metadata: signature_severity Major, created_et 2025_02_19;)\n\nalert tls $HOME_NET any -> any any (msg:"LureBarrier TLS SNI to suspicious domain - Phishing"; tls.sni; dataset:isset,phishing_domains,type string; reference:url,https://github.com/Adepoju/LureBarrier; reference:url,/AT/signature.html?sid=6000001; classtype:social-engineering; sid:6000001; rev:1; metadata: signature_severity Major, created_et 2025_02_19;)\n'

    current_time = datetime.now()
    gmt_offset = current_time.astimezone().strftime('%z')
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")

    header = f"""# Suricata LureBarrier rules
# Created by https://github.com/boluwaji/DomainSieve
# Last updated: {formatted_time} GMT{gmt_offset}
# SID range: 6000000-6100000
#
"""

    all_rules = [header, domain_rule] + rules

    with open(output_file, "w") as f:
        for rule in all_rules:
            f.write(rule)

    with open(output_file + ".md5", "w") as f:
        md5_hash = hashlib.md5(open(output_file, "rb").read()).hexdigest()
        f.write(md5_hash + "\n")

    with open(sid_file, "w") as f:
        f.write(str(sid))

    if os.path.exists(index_file):
        os.remove(index_file)

    print(f"Rulesets updated: {output_file}")
    if sid > 6100000:
        print("WARNING: SID range exceeded 6100000. Please consider adjusting the SID range.")

def main():
    if "--update" in sys.argv:
        update_from_index()
        return

    print(banner)
    print("\nStarting LureBarrier Update...\n")

    process_nrd_list()
    # Read the existing rules
    try:
        with open(output_file, "r") as f:
            existing_rules = f.readlines()
    except FileNotFoundError:
        existing_rules = []

    last_sid = get_last_sid()

    # Keep only the old HTTP rules (dropping headers and the old DNS rule)
    old_rules = [r for r in existing_rules if r.strip().startswith("alert http")]

    # Build a (host, path) index of the old rules for deduplication
    # This keeps a normal run after --update from recreating existing rules with new SIDs
    existing_keys = set()
    for rule in old_rules:
        m_host = re.search(r'http\.host; content:"([^"]+)"', rule)
        m_path = re.search(r'http\.uri; content:"([^"]+)"', rule)
        if m_host and m_path:
            existing_keys.add((m_host.group(1), m_path.group(1)))

    # Build the new rules
    print(f"Fetching URLs from {phishstats_url}...")
    phishstats_urls = fetch_phishing_urls(phishstats_url)
    phishstats, last_sid = create_suricata_rules(
        phishstats_urls, 
        'phishstats.info', 
        last_sid,
        existing_rules
    )
    
    print(f"\nFetching URLs from {openphish_url}...")
    openphish_urls = fetch_phishing_urls(openphish_url)
    openphish, last_sid = create_suricata_rules(
        openphish_urls, 
        'openphish.com', 
        last_sid,
        existing_rules
    )

    # Keep the fixed DNS rule and add the new rules
    domain_rule = 'alert dns $HOME_NET any -> any any (msg:"LureBarrier DNS query to suspicious domain - Phishing"; dns.query; dataset:isset,phishing_domains,type string; reference:url,https://github.com/boluwaji/DomainSieve; classtype:social-engineering; sid:6000000; rev:1; metadata: signature_severity Major, created_et 2025_02_19;)\n\nalert tls $HOME_NET any -> any any (msg:"LureBarrier TLS SNI to suspicious domain - Phishing"; tls.sni; dataset:isset,phishing_domains,type string; reference:url,https://github.com/Adepoju/LureBarrier; reference:url,/AT/signature.html?sid=6000001; classtype:social-engineering; sid:6000001; rev:1; metadata: signature_severity Major, created_et 2025_02_19;)\n'
    
    current_time = datetime.now()
    gmt_offset = current_time.astimezone().strftime('%z')
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    
    header = f"""# Suricata LureBarrier rules
# Created by https://github.com/boluwaji/DomainSieve
# Last updated: {formatted_time} GMT{gmt_offset}
# SID range: 6000000-6100000
#
"""

    # Drop any (host, path) from the new rules that already exists in the old
    # ones, avoiding duplicates after an --update that renumbered the SIDs
    def is_new_rule_unique(rule):
        m_host = re.search(r'http\.host; content:"([^"]+)"', rule)
        m_path = re.search(r'http\.uri; content:"([^"]+)"', rule)
        if m_host and m_path:
            return (m_host.group(1), m_path.group(1)) not in existing_keys
        return True

    unique_phishstats = [r for r in phishstats if is_new_rule_unique(r)]
    unique_openphish  = [r for r in openphish  if is_new_rule_unique(r)]

    removed = len(phishstats) + len(openphish) - len(unique_phishstats) - len(unique_openphish)
    if removed:
        print(f"Deduplication: {removed} rule(s) skipped (domain+path already in existing rules).")

    # Combina todas as regras
    all_rules = [header, domain_rule] + old_rules + unique_phishstats + unique_openphish

    # Write the rules to the file
    with open(output_file, "w") as f:
        for rule in all_rules:
            f.write(rule)

    # Generate the MD5 hash of the rules file for integrity checks (Suricata)
    with open(output_file, "rb") as f:
        md5_hash = hashlib.md5(f.read()).hexdigest()
    
    with open(output_file + ".md5", "w") as f:
        f.write(md5_hash + "\n")

    # Update the last SID
    with open(sid_file, "w") as f:
        f.write(str(last_sid))

    print(f"Rulesets updated: {output_file}")
    if last_sid > 6100000:
        print("WARNING: SID range exceeded 6100000. Please consider adjusting the SID range.")

if __name__ == "__main__":
    main()


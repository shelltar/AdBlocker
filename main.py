import requests
import re

# List of URLs containing ad blocking sources
urls = [
    'https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt',
    'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts',
    'https://v.firebog.net/hosts/static/w3kbl.txt',
    'https://adaway.org/hosts.txt',
    'https://v.firebog.net/hosts/AdguardDNS.txt',
    'https://v.firebog.net/hosts/Admiral.txt',
    'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt',
    'https://v.firebog.net/hosts/Easylist.txt',
    'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext',
    'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts',
    'https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts',
    'https://v.firebog.net/hosts/Easyprivacy.txt',
    'https://v.firebog.net/hosts/Prigent-Ads.txt',
    'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts',
    'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt',
    'https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt',
    'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt',
    'https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt',
    'https://v.firebog.net/hosts/Prigent-Crypto.txt',
    'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts',
    'https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt',
    'https://phishing.army/download/phishing_army_blocklist_extended.txt',
    'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt',
    'https://v.firebog.net/hosts/RPiList-Malware.txt',
    'https://v.firebog.net/hosts/RPiList-Phishing.txt',
    'https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt',
    'https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts',
    'https://urlhaus.abuse.ch/downloads/hostfile',
    'https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser'
    # Add more URLs as needed
]

# Function to download and parse content
def download_and_parse(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        content = response.text
        return content
    except requests.RequestException as e:
        print(f"Error downloading {url}: {e}")
        return ""

# Function to extract domains and IPs
def extract_domains(content):
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if re.match(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+', line):
            parts = line.split()
            if len(parts) == 2:
                domains.add(parts[1])
        elif re.match(r'^[0-9a-zA-Z.-]+\s*$', line):
            domains.add(line)
    return domains

# Set to store unique domains
all_domains = set()

# Process each URL
for url in urls:
    content = download_and_parse(url)
    if content:
        domains = extract_domains(content)
        all_domains.update(domains)

# Convert to AdAway style format and sort
adaway_format = sorted(f"127.0.0.1 {domain}" for domain in all_domains)

# Write to output file
output_file = 'AdAway.txt'
with open(output_file, 'w') as f:
    f.write("\n".join(adaway_format))

print(f"Combined ad block list saved to {output_file}")

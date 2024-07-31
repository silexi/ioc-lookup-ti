import requests
import json

# API Keys
ABUSEIPDB_API_KEY = 'your_abuseipdb_api_key_here'
VIRUSTOTAL_API_KEY = 'your_virustotal_api_key_here'

def check_abuseipdb(ip_address):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    return json.loads(response.text)

def check_virustotal_ip(ip_address):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    return json.loads(response.text)

def check_virustotal_domain(domain):
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    return json.loads(response.text)

def check_virustotal_url(url):
    url_encoded = requests.utils.quote(url, safe='')
    url = f'https://www.virustotal.com/api/v3/urls/{url_encoded}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    return json.loads(response.text)

def check_virustotal_hash(file_hash):
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    return json.loads(response.text)

def query_all_ti_sources(ioc, ioc_type):
    results = {}
    
    if ioc_type == "ip":
        results['AbuseIPDB'] = check_abuseipdb(ioc)
        results['VirusTotal'] = check_virustotal_ip(ioc)
    elif ioc_type == "domain":
        results['VirusTotal'] = check_virustotal_domain(ioc)
    elif ioc_type == "url":
        results['VirusTotal'] = check_virustotal_url(ioc)
    elif ioc_type == "hash":
        results['VirusTotal'] = check_virustotal_hash(ioc)
    
    return results

def determine_ioc_type(ioc):
    if ":" in ioc or "." in ioc:
        if ioc.count(".") == 3 and all(part.isdigit() for part in ioc.split(".")):
            return "ip"
        elif ioc.startswith("http://") or ioc.startswith("https://"):
            return "url"
        else:
            return "domain"
    elif len(ioc) in [32, 40, 64]:
        return "hash"
    else:
        return None

def main():
    ioc = input("Lütfen sorgulamak istediğiniz IOC'yi girin: ")
    ioc_type = determine_ioc_type(ioc)
    
    if ioc_type:
        results = query_all_ti_sources(ioc, ioc_type)
        for source, result in results.items():
            print(f"\n{source} sonuçları ({ioc_type}):")
            print(json.dumps(result, sort_keys=True, indent=4))
    else:
        print("Geçerli bir IOC türü belirlenemedi.")

if __name__ == "__main__":
    main()

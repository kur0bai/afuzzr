import argparse
import yaml
import json
import re
from colorama import Fore, Style, init
from http_client import FuzzerHttpClient
from payload_generator import PayloadGenerator
from reporter import Reporter

init(autoreset=True)


def show_banner():
    """
    Main identifier banner
    """  
    banner = [
        (Fore.GREEN + r"       __                    " ),
        (Fore.GREEN + r"      / _|                   " ),
        (Fore.GREEN + r"  __ _| |_ _   _ _________ __ " ),
        (Fore.GREEN + r" / _` |  _| | | |_  /_  / '__|" ),
        (Fore.CYAN + r"| (_| | | | |_| |/ / / /| |   " ),
        (Fore.CYAN + r" \__,_|_|  \__,_/___/___|_|   " ),
        (Fore.CYAN + r""),
        (Fore.CYAN + r"Author: kur0bai"),
        (Fore.YELLOW + r"Visit: https://github.com/kur0bai"),
        Style.RESET_ALL
    ]

    for line in banner:
        print(line)



def load_openapi_spec(file_path: str) -> dict:
    """
    Just open the path of specs if specified
    """
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            return yaml.safe_load(f)
        return json.load(f)


def load_wordlist(file_path: str) -> list:
    """
    Open wordlist based on path
    """
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]        

def get_args():
    parser = argparse.ArgumentParser(description="Easy way to fuzz APIs")
    parser.add_argument("--url", type=str,
                        required=True,
                        help="The Target URL to fuzz")
    parser.add_argument("--specs", type=str, 
                        required=False, 
                        help="The openapi.json file (Optional)")
    parser.add_argument("--mode", choices=['spec', 'dict'],
                        required=False, help="Mode", default="dict")                   
    args = parser.parse_args()
    return args


def fuzz_with_spec(spec, base_url, client, generator, reporter):
    print(f"{Fore.CYAN}[*] Starting fuzzing by specs...")
    paths = spec.get('paths', {})
    paths = spec.get('paths', {})
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() not in ['GET', 'POST', 'PUT']:
                continue
            
            print(f"\n{Fore.YELLOW}[+] Analyzing {method.upper()} {path}")

 
            parameters = details.get('parameters', [])
            path_params = [p for p in parameters if p['in'] == 'path']
            query_params = [p for p in parameters if p['in'] == 'query']

  
            request_body = details.get('requestBody', {})
            content = request_body.get('content', {})
            json_content = content.get('application/json', {})
            body_schema = json_content.get('schema', {})
            body_properties = body_schema.get('properties', {})


            for param in path_params:
                param_name = param['name']
                param_type = param['schema'].get('type', 'string')
                payloads = generator.generate(param_name, param_type)
                
                for payload in payloads:
                    fuzzed_path = path.replace(f"{{{param_name}}}", str(payload))
                    status_code, _, response_text, duration_ms = client.send_request(method, fuzzed_path, {})
                    if status_code >= 400 or duration_ms > 5000:
                        reason = f"Path param '{param_name}' fuzzed. Status: {status_code}, Time: {duration_ms:.2f}ms"
                        reporter.add_finding(method, fuzzed_path, {"payload": payload}, reason, response_text, "high")
                        print(f"{Fore.RED}[!] ANOMALY in PATH: {reason}")

          
            for param in query_params:
                param_name = param['name']
                param_type = param['schema'].get('type', 'string')
                payloads = generator.generate(param_name, param_type)

                for payload in payloads:
                    params = {param_name: payload}
                    status_code, _, response_text, duration_ms = client.send_request(method, path, {}, params=params)
                    if status_code >= 400 or duration_ms > 5000:
                        reason = f"Query param '{param_name}' fuzzed. Status: {status_code}, Time: {duration_ms:.2f}ms"
                        reporter.add_finding(method, path, {"payload": payload}, reason, response_text, "high")
                        print(f"{Fore.RED}[!] ANOMALY in QUERY: {reason}")

            
            if body_properties:
                for prop_name, prop_schema in body_properties.items():
                    prop_type = prop_schema.get('type', 'string')
                    payloads_to_test = generator.generate(prop_name, prop_type)
                    
                    for payload in payloads_to_test:
                        fuzz_payload = {k: "sample_data" for k in body_properties.keys()}
                        fuzz_payload[prop_name] = payload

                        status_code, _, response_text, duration_ms = client.send_request(method, path, fuzz_payload)

def fuzz_with_dict(base_url, client, generator, reporter):
    print(f"{Fore.CYAN}[*] Starting fuzzing in dict mode...")
    endpoints = load_wordlist('wordlists/endpoints.txt')
    parameters = load_wordlist('wordlists/parameters.txt')
    methods = ['GET', 'POST', 'PUT', 'DELETE']

    print(f"\n{Fore.MAGENTA}[+] Fase 1: Endpoints discovering...")
    discovered_endpoints = set()
    for endpoint in endpoints:
        status_code, _, response_text, _ = client.send_request('GET', f"/{endpoint}", {})
        if status_code == 200:
            print(f"{Fore.GREEN}[+] Endpoint found: GET {base_url}/{endpoint}")
            discovered_endpoints.add(f"/{endpoint}")
        elif status_code != 404: 
             print(f"{Fore.YELLOW}[?] Unexpected response ({status_code}) in: GET /{endpoint}")
             discovered_endpoints.add(f"/{endpoint}")
    
    if not discovered_endpoints:
        print(f"{Fore.LIGHTBLACK_EX}[-] No Endpoints found. Quiting.")
        return

    # Fuzzin magic
    print(f"\n{Fore.MAGENTA}[+] Phase 2: Starting to FUZZ discovered endpoints")
    for path in discovered_endpoints:
        for method in methods:
            print(f"\n{Fore.YELLOW}[+] Fuzzing {method.upper()} {path}")
            for param_name in parameters:
                payloads = generator.generate(param_name, 'string')
                
                for payload in payloads:
                    if method == 'GET':
                        params = {param_name: payload}
                        status_code, _, response_text, duration_ms = client.send_request(method, path, {})
                        if status_code >= 500 or duration_ms > 5000:
                            reason = f"Dict-Fuzz (Query): '{param_name}'='{payload}'. Status: {status_code}, Time: {duration_ms:.2f}ms"
                            reporter.add_finding(method, path, {"payload": payload}, reason, response_text, "critical")
                            print(f"{Fore.RED}[!] CRITIC ANOMALY: {reason}")
                    
       
                    if method in ['POST', 'PUT']:
                        body_payload = {param_name: payload}
                        status_code, _, response_text, duration_ms = client.send_request(method, path, body_payload)
                        if status_code >= 500 or duration_ms > 5000:
                            reason = f"Dict-Fuzz (Body): '{param_name}'='{payload}'. Status: {status_code}, Time: {duration_ms:.2f}ms"
                            reporter.add_finding(method, path, {"payload": payload}, reason, response_text, "critical")
                            print(f"{Fore.RED}[!] CRITIC ANOMALY: {reason}")    


def main():
    show_banner()
    args = get_args()
    base_url = args.url
    spec_path = args.specs
    mode = args.mode

    client = FuzzerHttpClient(base_url)
    generator = PayloadGenerator()
    reporter = Reporter()

    if mode == 'dict':
        fuzz_with_dict(base_url, client, generator, reporter)
    elif mode == 'spec':
        if not spec_path:
            print(f"{Fore.RED}[!] Error: The 'spec' mode requires the argument --spec.")
            return
        spec = load_openapi_spec(spec_path)
        fuzz_with_spec(spec, base_url, client, generator, reporter)


    print(f"\n{Fore.GREEN}[*] Fuzzing completed.")
    reporter.save_report('fuzzer_report.html')

if __name__ == "__main__":
    import os
    main()

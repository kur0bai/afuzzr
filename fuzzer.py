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

def get_args():
    parser = argparse.ArgumentParser(description="Easy way to fuzz APIs")
    parser.add_argument("--url", type=str,
                        required=True,
                        help="The Target URL to fuzz")
    parser.add_argument("--specs", type=str, 
                        required=False, 
                        help="The openapi.json file (Optional)")
    parser.add_argument("--mode", choices=['spec', 'dict'],
                        required=False, help="Mode")                   
    args = parser.parse_args()
    return args

def main():
    show_banner()
    args = get_args()
    base_url = args.url
    spec_path = args.specs
    mode = args.mode

    if spec_path:
        print(f"{Fore.CYAN}[*] Loading OpenAPI specs from: {spec_path}")
        try:
            spec = load_openapi_spec(spec_path)
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Error: El archivo de especificación no se encuentra en '{spec_path}'")
            print(f"{Fore.YELLOW}[+] Descargando una API de ejemplo (Petstore)...")
            import urllib.request
            os.makedirs('examples', exist_ok=True)
            urllib.request.urlretrieve("https://petstore.swagger.io/v2/swagger.json", spec_path)
            spec = load_openapi_spec(spec_path)
            print(f"{Fore.GREEN}[+] API de ejemplo descargada y cargada.")

    client = FuzzerHttpClient(base_url)
    generator = PayloadGenerator()
    reporter = Reporter()

    paths = spec.get('paths', {})
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() not in ['POST', 'PUT']:
                continue
            
            print(f"\n{Fore.YELLOW}[+] Fuzzing {method.upper()} {path}")
            
            request_body = details.get('requestBody', {})
            content = request_body.get('content', {})
            json_content = content.get('application/json', {})
            schema = json_content.get('schema', {})
            
            properties = schema.get('properties', {})
            if not properties:
                print(f"{Fore.LIGHTBLACK_EX}[-] Not Body JSON found. Skipping.")
                continue

            # Fuzzing by each one
            for prop_name, prop_schema in properties.items():
                prop_type = prop_schema.get('type', 'string')
                
                payloads_to_test = generator.generate(prop_name, prop_type)
                
                for i, payload in enumerate(payloads_to_test):
                    # Create a valid apyload
                    fuzz_payload = {k: "sample_data" for k in properties.keys()}
                    fuzz_payload[prop_name] = payload

                    status_code, headers, response_text, duration_ms = client.send_request(method, path, fuzz_payload)
                    
                    # Intelligent detection
                    is_anomaly = False
                    reason = ""

                    
                    if status_code >= 500:
                        is_anomaly = True
                        reason = f"Server Error ({status_code})"
                        reporter.add_finding(method, path, fuzz_payload, reason, response_text, "critical")

                    # Info leaks
                    if re.search(r"stack trace|syntax error|fatal error|exception", response_text, re.IGNORECASE):
                        is_anomaly = True
                        reason = "Information Leak (Error Details)"
                        reporter.add_finding(method, path, fuzz_payload, reason, response_text, "high")
                    
                    # (Blind SQLi/Command Injection)
                    if duration_ms > 5000 and status_code < 500:
                        is_anomaly = True
                        reason = f"Significant Time Delay ({duration_ms:.2f}ms) - Possible Blind Injection"
                        reporter.add_finding(method, path, fuzz_payload, reason, response_text, "critical")
                    
                    
                    if status_code == 422 and "validation" not in response_text.lower():
                        is_anomaly = True
                        reason = "Unprocessable Entity - Possible Logic Error"
                        reporter.add_finding(method, path, fuzz_payload, reason, response_text, "medium")

                    if is_anomaly:
                        print(f"{Fore.RED}[!] ANOMALY DETECTED: {reason} | Payload: {fuzz_payload}")
                    else:
                        print(f"{Fore.LIGHTBLACK_EX}[...] Status {status_code} | Payload: {str(payload)[:50]}...")

    print(f"\n{Fore.GREEN}[*] Fuzzing completed.")
    reporter.save_report('fuzzer_report.html')

if __name__ == "__main__":
    import os
    main()
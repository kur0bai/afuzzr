import yaml
import json
import re
from colorama import Fore, Style, init
from http_client import FuzzerHttpClient
from payload_generator import PayloadGenerator
from reporter import Reporter

init(autoreset=True)

def load_openapi_spec(file_path: str) -> dict:
    with open(file_path, 'r') as f:
        if file_path.endswith('.yaml') or file_path.endswith('.yml'):
            return yaml.safe_load(f)
        return json.load(f)

def main():
    spec_path = 'examples/petstore_openapi.json'
    base_url = "https://petstore.swagger.io/v2"

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
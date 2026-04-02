import random
from colorama import Fore, Style
from utils.file import Utils
from utils.header import Header

class Fuzzer():

    def is_real_endpoint(self, baseline_len: int, baseline_body: str, status_code: int, body: str) -> tuple[bool, str]:
            """
            Validate if the endpoint is real based on baseline
            """
            LOGIN_PATTERNS = ["/login", "/signin", "/auth", "/session", "/account"]
            login_in_baseline = any(p in baseline_body.lower() for p in LOGIN_PATTERNS)

            if status_code in [401, 403, 405]:
                return True, f"Protected ({status_code})"

            if status_code in [301, 302, 307, 308]:
                return True, "Redirect (exists)"

            if status_code == 404:
                return False, "Hard 404"

            if status_code == 200:
                body_len = len(body)


                if baseline_len > 0:
                    diff       = abs(body_len - baseline_len)
                    similarity = 1 - (diff / max(body_len, baseline_len))
                    if similarity > 0.92:
                        return False, f"Soft 404 (body {similarity:.0%} match with baseline)"


                if login_in_baseline:
                    if any(p in body.lower() for p in LOGIN_PATTERNS):
                        return False, "Redirected to login (soft 404)"


                error_keywords = ["not found", "404", "page not found",
                                "no encontrado", "doesn't exist", "invalid page"]
                for kw in error_keywords:
                    if kw in body.lower():
                        return False, f"Soft 404 (keyword: '{kw}')"

                return True, f"Valid 200 (length={body_len})"

            return False, f"Unhandled status {status_code}"

    def calibrate_baseline(self,client):
        """
        Calibrate Baseline to avoid fuzz endpoints that doesnt exists
        """
        print(f"{Fore.WHITE}[•] CALIBRATED baseline (soft-404 detection){Style.RESET_ALL}")

        fake_path = f"/__baseline_does_not_exist_{random.randint(10000, 99999)}__"
        bl_status, _, bl_body, _ = client.send_request('GET', fake_path, {})
        baseline_len  = len(bl_body)
        baseline_body = bl_body

        print(f"{Fore.WHITE}    Baseline status :{Fore.CYAN}{bl_status}")
        print(f"{Fore.WHITE}    Baseline length  : {Fore.CYAN}{baseline_len} chars")

        return baseline_len, baseline_body

    def fuzz_discovered_endpoints(self, discovered_endpoints, methods, parameters, generator, client, reporter, verbose=False):
        for path in discovered_endpoints:
            for path in discovered_endpoints:
                for method in methods:
                    print(f"{Fore.WHITE}[•] Fuzzing {Fore.YELLOW}{method.upper()} {path}")
                    print(f"{Fore.WHITE}    Params to test : {Fore.CYAN}{len(parameters)}")
                    print(f"{Fore.WHITE}    Payloads/param  : {Fore.CYAN}{sum(len(generator.generate(p, 'string')) for p in parameters)}")
                    print(f"{Fore.WHITE}{'═'*72}{Style.RESET_ALL}")

                    total_requests = 0
                    findings_in_path = 0

                    for param_name in parameters:
                        payloads = generator.generate(param_name, 'string')
                        print(f"\n{Fore.CYAN}  [*] Parameter: '{param_name}' — {len(payloads)} payloads{Style.RESET_ALL}")

                        for i, payload in enumerate(payloads, 1):
                            if payload is None:
                                payload_str = "null"
                                payload_repr = "None (null test)"
                            elif payload == "":
                                payload_str = ""
                                payload_repr = '"" (empty string test)'
                            else:
                                payload_str = str(payload)
                                payload_repr = repr(payload_str[:40] + "..." if len(payload_str) > 40 else payload_str)

                            print(f"{Fore.WHITE}      [{i:03}/{len(payloads):03}] Payload: {payload_repr}{Style.RESET_ALL}", end="\r")

                            if method == 'GET':
                                params = {param_name: payload}
                                status_code, _, response_text, duration_ms = client.send_request(method, path, {})
                                total_requests += 1

                                # Verbose
                                if verbose:
                                    status_color = Fore.GREEN if status_code < 400 else (Fore.YELLOW if status_code < 500 else Fore.RED)
                                    print(f"      [{i:03}/{len(payloads):03}] "
                                        f"GET {path}?{param_name}=... | "
                                        f"{status_color}{status_code}{Style.RESET_ALL} | "
                                        f"{duration_ms:.1f}ms{' ⚠ SLOW' if duration_ms > 5000 else ''}")

                                    if status_code >= 500 or duration_ms > 5000:
                                        findings_in_path += 1
                                        reason = (f"Dict-Fuzz (Query): '{param_name}'='{payload}'. "
                                                f"Status: {status_code}, Time: {duration_ms:.2f}ms")
                                        reporter.add_finding(method, path, {"payload": payload}, reason, response_text, "critical")
                                        print(f"\n{Fore.RED}  [!!!] CRITICAL ANOMALY DETECTED")
                                        print(f"        Method   : {method}")
                                        print(f"        Path     : {path}")
                                        print(f"        Param    : {param_name}")
                                        print(f"        Payload  : {repr(payload)}")
                                        print(f"        Status   : {status_code}")
                                        print(f"        Duration : {duration_ms:.2f}ms")
                                        print(f"        Snippet  : {response_text[:120]!r}")
                                        print(f"{Style.RESET_ALL}")

                            if method in ['POST', 'PUT']:
                                body_payload = {param_name: payload}
                                status_code, _, response_text, duration_ms = client.send_request(method, path, body_payload)
                                total_requests += 1

                                if verbose:    
                                    status_color = Fore.GREEN if status_code < 400 else (Fore.YELLOW if status_code < 500 else Fore.RED)
                                    print(f"      [{i:03}/{len(payloads):03}] "
                                        f"{method} {path} body={{{param_name}: ...}} | "
                                        f"{status_color}{status_code}{Style.RESET_ALL} | "
                                        f"{duration_ms:.1f}ms{' ⚠ SLOW' if duration_ms > 5000 else ''}")

                                    if status_code >= 500 or duration_ms > 5000:
                                        findings_in_path += 1
                                        reason = (f"Dict-Fuzz (Body): '{param_name}'='{payload}'. "
                                                f"Status: {status_code}, Time: {duration_ms:.2f}ms")
                                        reporter.add_finding(method, path, {"payload": payload}, reason, response_text, "critical")
                                        print(f"\n{Fore.RED}  [!!!] CRITICAL ANOMALY DETECTED")
                                        print(f"        Method   : {method}")
                                        print(f"        Path     : {path}")
                                        print(f"        Param    : {param_name}")
                                        print(f"        Payload  : {repr(payload)}")
                                        print(f"        Status   : {status_code}")
                                        print(f"        Duration : {duration_ms:.2f}ms")
                                        print(f"        Snippet  : {response_text[:120]!r}")
                                        print(f"{Style.RESET_ALL}")

                    # Resume
                    print(f"\n{Fore.CYAN}  [SUMMARY] {method.upper()} {path}")
                    print(f"            Requests sent : {total_requests}")
                    print(f"            Findings      : {Fore.RED if findings_in_path else Fore.GREEN}{findings_in_path}{Style.RESET_ALL}")

    def fuzz_with_spec(self, spec, base_url, client, generator, reporter):
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

    def fuzz_with_dict(self, base_url, client, generator, reporter, wordlist=None, verbose=False, success=False):
        """
        FUZZ using dictionaries, given or default
        """

        load_wordlist = Utils().load_wordlist
        # Print MODE
        print(f"{Fore.WHITE}[•] Running on {Fore.YELLOW}Dictionary{Fore.WHITE} MODE")

        # Load default parameters if not specified
        endpoints  = load_wordlist('wordlists/endpoints.txt') if wordlist is None else  load_wordlist(wordlist)
        parameters = load_wordlist('wordlists/parameters.txt')
        methods    = ['GET', 'POST', 'PUT', 'DELETE']


        #Calibrate baseline to detect soft redirect
        baseline_len, baseline_body = self.calibrate_baseline(client=client)

        # Init fuzzing directories
        header =  Header()
        header.print_header("Endpoint Discovering", "🌐")

        discovered_endpoints = set()
        total_checked = 0

        for endpoint in endpoints:
            path = f"{endpoint}"
            status_code, _, response_text, duration_ms = client.send_request('GET', path, {})
            total_checked += 1

            valid, reason = self.is_real_endpoint(baseline_len=baseline_len, baseline_body=baseline_body, status_code=status_code, body=response_text)

            status_color = (Fore.GREEN  if status_code < 300 else
                            Fore.YELLOW if status_code < 500 else Fore.RED)

            if valid:
                discovered_endpoints.add(path)
                print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {base_url}{path:<35} "
                    f"{status_color}{status_code}{Style.RESET_ALL}  "
                    f"{duration_ms:>7.1f}ms  {Fore.GREEN}{reason}{Style.RESET_ALL}")
            else:
                if not success:
                    print(f"  {Fore.RED}[x]{Style.RESET_ALL} {base_url}{path:<35} "
                        f"{status_color}{status_code}{Style.RESET_ALL}  "
                        f"{duration_ms:>7.1f}ms  {Fore.RED}{reason}{Style.RESET_ALL}")

        print(f"\n{Fore.WHITE}{'═' * 72}")
        print(f"  Checked    : {total_checked} endpoints")
        print(f"  Discovered : {Fore.GREEN}{len(discovered_endpoints)}{Fore.CYAN} valid endpoints")
        print(f"  Rejected   : {Fore.RED}{total_checked - len(discovered_endpoints)}{Fore.CYAN} soft/hard 404s")


        if not discovered_endpoints:
            print(Fore.RED + "  [-] No endpoints found.")
            return


        # Start Fuzzing magic
        header.print_header("Endpoint Fuzzing", "🌐")

        self.fuzz_discovered_endpoints(discovered_endpoints, methods, parameters, generator, client,reporter, verbose)

        


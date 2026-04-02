import random
import re
from colorama import Fore, Style
from core.payload_inspector import EndpointInspector
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

    def _infer_param_type(self, param_name: str, intel: dict) -> str:
        """
        Infer in the data type spected
        """
        p = param_name.lower()
        if any(k in p for k in ['id', 'count', 'page', 'limit', 'offset', 'age', 'year']):
            return 'integer'
        if any(k in p for k in ['active', 'enabled', 'verified', 'admin', 'flag']):
            return 'boolean'
        return 'string'

    def _detect_anomaly(self, status_code: int, duration_ms: float, body: str) -> str | None:
        """
        Detect anomalies in the response
        """
        if status_code >= 500:
            return f"Server error ({status_code})"
        if duration_ms > 5000:
            return f"Time-based anomaly ({duration_ms:.0f}ms) — possible blind injection"
        if status_code == 200 and duration_ms > 3000:
            return f"Suspicious delay ({duration_ms:.0f}ms)"

        error_traces = ['traceback', 'stack trace', 'exception', 'sqlexception',
                        'syntaxerror', 'undefined method', 'null pointer']
        body_lower = body.lower()
        for trace in error_traces:
            if trace in body_lower:
                return f"Error trace in response ('{trace}')"

        # SQL errors
        sql_errors = ['sql syntax', 'mysql_fetch', 'ora-0', 'pg::',
                      'sqlite3::', 'unclosed quotation']
        for err in sql_errors:
            if err in body_lower:
                return f"SQL error in response ('{err}')"

        return None

    def _get_severity(self, status_code: int, duration_ms: float, intel: dict) -> str:
        """
        If critic or not
        """
        if intel["schema"]["sensitive_fields"] and status_code >= 500:
            return "critical"
        if duration_ms > 5000:
            return "high"    
        if status_code >= 500:
            return "high"
        return "medium"

    def _print_request_line(self, i, total, method, path, param,
                             status_code, duration_ms, anomaly):
        status_color = (Fore.GREEN  if status_code < 400 else
                        Fore.YELLOW if status_code < 500 else Fore.RED)
        slow_flag  = " ⚠ SLOW"    if duration_ms > 3000 else ""
        anomaly_flag = f" {Fore.RED}⚡ ANOMALY{Style.RESET_ALL}" if anomaly else ""
        print(f"      [{i:03}/{total:03}] {method} {path}?{param}=... | "
              f"{status_color}{status_code}{Style.RESET_ALL} | "
              f"{duration_ms:.1f}ms{slow_flag}{anomaly_flag}")

    def _print_anomaly(self, method, path, param, payload,
                        status_code, duration_ms, body, anomaly, severity):
        sev_color = Fore.RED if severity == 'critical' else Fore.YELLOW
        print(f"\n{sev_color}  ┌─ [{severity.upper()}] ANOMALY DETECTED")
        print(f"  ├─ Method   : {method}")
        print(f"  ├─ Path     : {path}")
        print(f"  ├─ Param    : {param}")
        print(f"  ├─ Payload  : {repr(payload)}")
        print(f"  ├─ Status   : {status_code}")
        print(f"  ├─ Duration : {duration_ms:.2f}ms")
        print(f"  ├─ Anomaly  : {anomaly}")
        print(f"  └─ Snippet  : {body[:120]!r}{Style.RESET_ALL}\n")


    def fuzz_discovered_endpoints(self, discovered_endpoints, methods, parameters, generator, client, reporter, verbose=False):
        inspector = EndpointInspector(client)

        for path in discovered_endpoints:
            for path in discovered_endpoints:
                for method in methods:

                    # Using intel from inspector
                    print(f"\n{Fore.CYAN}  [INSPECT] {method} {path}{Style.RESET_ALL}")
                    intel = inspector.inspect(method, path)

                    if intel["technology_hints"]:
                        print(f"  {Fore.YELLOW}[TECH] {', '.join(intel['technology_hints'])}{Style.RESET_ALL}")
                    if intel["auth"]["required"]:
                        print(f"  {Fore.YELLOW}[AUTH] Authentication required{Style.RESET_ALL}")
                    if intel["schema"]:
                        print(f"  {Fore.YELLOW}[SCHEMA] Response keys: {intel['schema']}{Style.RESET_ALL}")


                    if not intel["should_fuzz"]:
                        print(f"  {Fore.RED}[SKIP] {path} — no attack surface (score={intel['attack_surface_score']}){Style.RESET_ALL}")
                        continue
                    
                    priority_params = (
                        intel["path_params"] +
                        intel["schema"]["sensitive_fields"] +
                        intel["schema"]["nested_objects"]
                    )

                    remaining_params = [p for p in parameters if p not in priority_params]
                    active_params = priority_params + remaining_params

                    print(f"\n{Fore.WHITE}[•] Fuzzing {Fore.YELLOW}{method.upper()} {path}")
                    print(f"{Fore.WHITE}    Attack score   : {Fore.CYAN}{intel['attack_surface_score']}/10")
                    print(f"{Fore.WHITE}    Active params  : {Fore.CYAN}{len(active_params)} "
                        f"({len(priority_params)} priority + {len(remaining_params)} wordlist)")
                    print(f"{Fore.WHITE}    Total payloads : {Fore.CYAN}"
                        f"{sum(len(generator.generate(p, 'string')) for p in active_params)}")
                    print(f"{Fore.WHITE}{'═' * 72}{Style.RESET_ALL}")

                    total_requests   = 0
                    findings_in_path = 0

                    for param_name in active_params:
                        
                        data_type = self._infer_param_type(param_name, intel)
                        payloads  = generator.generate(param_name, data_type)

                        is_priority = param_name in priority_params
                        param_label = f"{Fore.YELLOW}[PRIORITY]{Fore.CYAN}" if is_priority else f"{Fore.WHITE}[wordlist]{Fore.CYAN}"

                        print(f"\n{Fore.CYAN}  [*] {param_label} '{param_name}' "
                            f"— {len(payloads)} payloads (type={data_type}){Style.RESET_ALL}")


                        for i, payload in enumerate(payloads, 1):
                            if payload is None:
                                payload_str  = "null"
                                payload_repr = "None (null test)"
                            elif payload == "":
                                payload_str  = ""
                                payload_repr = '"" (empty string)'
                            else:
                                payload_str  = str(payload)
                                payload_repr = repr(payload_str[:40] + "..." if len(payload_str) > 40 else payload_str)

                            # GET method
                            if method == 'GET':
                                status_code, _, response_text, duration_ms = client.send_request(
                                    method, path, {param_name: payload_str}
                                )
                                total_requests += 1

                                anomaly = self._detect_anomaly(status_code, duration_ms, response_text)

                                if verbose:
                                    self._print_request_line(i, len(payloads), method, path,
                                                            param_name, status_code, duration_ms, anomaly)

                                if anomaly:
                                    findings_in_path += 1
                                    reason = (f"Dict-Fuzz (Query): '{param_name}'='{payload_str}'. "
                                            f"Status: {status_code}, Time: {duration_ms:.2f}ms, "
                                            f"Anomaly: {anomaly}")
                                    severity = self._get_severity(status_code, duration_ms, intel)
                                    reporter.add_finding(method, path, {"payload": payload},
                                                        reason, response_text, severity)
                                    self._print_anomaly(method, path, param_name, payload_str,
                                                        status_code, duration_ms, response_text,
                                                        anomaly, severity)

                            # POST / PUT / PATCH Methods
                            if method in ['POST', 'PUT', 'PATCH']:
                                body_payload = {param_name: payload_str}
                                status_code, _, response_text, duration_ms = client.send_request(
                                    method, path, body_payload
                                )
                                total_requests += 1

                                anomaly = self._detect_anomaly(status_code, duration_ms, response_text)

                                if verbose:
                                    self._print_request_line(i, len(payloads), method, path,
                                                            param_name, status_code, duration_ms, anomaly)

                                if anomaly:
                                    findings_in_path += 1
                                    reason = (f"Dict-Fuzz (Body): '{param_name}'='{payload_str}'. "
                                            f"Status: {status_code}, Time: {duration_ms:.2f}ms, "
                                            f"Anomaly: {anomaly}")
                                    severity = self._get_severity(status_code, duration_ms, intel)
                                    reporter.add_finding(method, path, {"payload": payload},
                                                        reason, response_text, severity)
                                    self._print_anomaly(method, path, param_name, payload_str,
                                                        status_code, duration_ms, response_text,
                                                        anomaly, severity)

                            # DELETE method
                            if method == 'DELETE' and param_name in intel["path_params"]:
                                fuzz_path = re.sub(
                                    rf'\{{param_name\}}|:({param_name})|<[^>]*{param_name}[^>]*>',
                                    payload_str, path
                                )
                                status_code, _, response_text, duration_ms = client.send_request(
                                    'DELETE', fuzz_path, {}
                                )
                                total_requests += 1

                                anomaly = self._detect_anomaly(status_code, duration_ms, response_text)

                                if verbose:
                                    self._print_request_line(i, len(payloads), 'DELETE', fuzz_path,
                                                            param_name, status_code, duration_ms, anomaly)

                                if anomaly:
                                    findings_in_path += 1
                                    reason = (f"Dict-Fuzz (Path): DELETE {fuzz_path}. "
                                            f"Status: {status_code}, Time: {duration_ms:.2f}ms")
                                    severity = self._get_severity(status_code, duration_ms, intel)
                                    reporter.add_finding('DELETE', fuzz_path, {"payload": payload},
                                                        reason, response_text, severity)
                                    self._print_anomaly('DELETE', fuzz_path, param_name, payload_str,
                                                        status_code, duration_ms, response_text,
                                                        anomaly, severity)

                        

                    # Resume
                    severity_color = Fore.RED if findings_in_path >= 3 else \
                             Fore.YELLOW if findings_in_path >= 1 else Fore.GREEN

                    print(f"\n{Fore.CYAN}  ┌─ SUMMARY {method.upper()} {path}")
                    print(f"  ├─ Requests sent : {total_requests}")
                    print(f"  ├─ Findings      : {severity_color}{findings_in_path}{Fore.CYAN}")
                    print(f"  └─ Params tested : {len(active_params)} "
                        f"({len(priority_params)} priority){Style.RESET_ALL}")

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

        


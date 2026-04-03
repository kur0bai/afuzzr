import json
import re
from colorama import Fore, Style

from core.fields import Fields

class APIInspector:

    def __init__(self, client):
        self.client = client
        self.core_fields = Fields()

    def inspect(self, method: str, path: str) -> dict:
        status, headers, body, _ = self.client.send_request(method, path)
        
        intel = {
            "method": method,
            "path": path,
            "status": status,
            "vectors": self._analyze_attack_vectors(method, path, status, body, headers)
        }
        
        return intel

    def _analyze_api_schema(self, body: str) -> dict:
        """Extract keys and types to detect mass"""
        try:
            data = json.loads(body)
            if isinstance(data, list) and len(data) > 0: data = data[0]
            if not isinstance(data, dict): return {"fields": [], "types": {}}
            
            return {
                "fields": list(data.keys()),
                "types": {k: type(v).__name__ for k, v in data.items()},
                "count": len(data.keys())
            }
        except:
            return {"fields": [], "types": {}}

    def _analyze_attack_vectors(self, method: str, path: str, status: int, body: str, headers: dict) -> list:
        vectors = []
        content_type = headers.get("Content-Type", "").lower()

        if path.endswith('/') or "list" in path.lower():
            vectors.append({
                "type": "ID_ENUMERATION",
                "confidence": "MEDIUM",
                "description": "Endpoint looks like a collection. Suggest fuzzing for numeric or UUID patterns to find valid resources."
            })

        # 1. BOLA Vector (ID en Path or Body)
        if "{" in path or ":" in path or "<" in path:
            vectors.append({
                "type": "BOLA_PATH",
                "confidence": "HIGH",
                "description": "ID detected in URL path. High chance of IDOR/BOLA."
            })
            
        # 2. Excessive Data Exposure / PII
        is_doc = any(doc in path.lower() for doc in self.core_fields.DOCUMENTATION_PATHS)
        is_html = "text/html" in content_type

        if not is_doc:
            if is_html:
                critical_patterns = self.core_fields.HTML_CRITICAL_PATTERNS
                found_critical = [p for p in critical_patterns if p in body]
                if found_critical:
                    vectors.append({
                        "type": "SENSITIVE_LEAK_IN_HTML",
                        "confidence": "HIGH",
                        "description": f"Hardcoded secrets found in HTML view: {found_critical}"
                    })
            else:
                pii_patterns = self.core_fields.PII_PATTERNS
                found_pii = [p for p in pii_patterns if p in body.lower()]
                if found_pii:
                    vectors.append({
                        "type": "DATA_EXPOSURE",
                        "confidence": "MEDIUM",
                        "description": f"Sensitive fields found in response: {found_pii}"
                    })

        # 3. Mass Assignment
        if method in ["GET", "PUT", "PATCH"]:
            try:
                fields = json.loads(body).keys()
                sensitive_fields = self.core_fields.SENSITIVE_FIELDS
                matches = [f for f in fields if any(s in f.lower() for s in sensitive_fields)]
                if matches:
                    vectors.append({
                        "type": "MASS_ASSIGNMENT",
                        "confidence": "HIGH",
                        "description": f"Modifiable sensitive fields candidate: {matches}"
                    })
            except: pass

        return vectors

    def _discover_ids(self, path: str) -> list:
        discovered = []
        seeds = ["1", "1000", "0", "me", "self", "admin"]
        for seed in seeds:
            test_path = f"{path.rstrip('/')}/{seed}"
            status, _, body, _ = self.client.send_request("GET", test_path)
            if status == 200:
                discovered.append(seed)
                # Si el body trae más IDs dentro (ej: una lista de amigos), los extraemos
                discovered.extend(self._extract_ids_from_response(body))
        
        return list(set(discovered))

    def _detect_sensitive_fields(self, body: str) -> list:
        findings = []
        patterns = {
            "PII_EMAIL": r'[\w\.-]+@[\w\.-]+\.\w+',
            "INTERNAL_IP": r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            "CREDIT_CARD": r'\b(?:\d[ -]*?){13,16}\b'
        }
        for name, regex in patterns.items():
            if re.search(regex, body):
                findings.append(name)
        return findings

    def _print_enhanced_intel(self, intel):
        print(f"\n{Fore.YELLOW}🔍 API INSPECTION: {intel['method']} {intel['path']}")
        
        # BOLA Indicator 
        bola_color = Fore.RED if intel["bola_target"] else Fore.GREEN
        print(f"  ├─ BOLA Risk      : {bola_color}{intel['bola_target']}{Style.RESET_ALL}")
        
        # Mass Assignment Indicator
        ma_color = Fore.RED if intel["mass_assignment_risk"] else Fore.YELLOW
        print(f"  ├─ Mass Assignment: {ma_color}{intel['mass_assignment_risk']}{Style.RESET_ALL}")
        
        # Detected field
        if intel["schema"]["fields"]:
            fields_str = ", ".join(intel["schema"]["fields"][:6])
            print(f"  ├─ Detected Fields: {Fore.CYAN}{fields_str}... ({intel['schema']['count']} total)")
            
        # Sensitive data
        if intel["sensitive_data"]:
            print(f"  └─ {Fore.LIGHTRED_EX}EXPOSURE ALERT: {intel['sensitive_data']}{Style.RESET_ALL}")
        else:
            print(f"  └─ Exposure       : {Fore.GREEN}Clean (No PII detected){Style.RESET_ALL}")
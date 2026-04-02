import re
import json
from colorama import Fore, Style

class EndpointInspector:
    def __init__(self, client):
        self.client = client

        self.PATH_PARAM_PATTERNS = [
            r'\{(\w+)\}',           # /users/{id}
            r'/:(\w+)',             # /users/:id  (Express)
            r'/<(\w+)>',           # /users/<id> (Flask)
            r'/<int:(\w+)>',       # /users/<int:id>
            r'/<str:(\w+)>',       # /users/<str:name>
            r'/\[(\w+)\]',         # /users/[id]  (Next.js)
        ]

    
        self.TECH_SIGNATURES = {
            'express':      'Node/Express',
            'nestjs':       'Node/NestJS',
            'fastify':      'Node/Fastify',
            'django':       'Python/Django',
            'flask':        'Python/Flask',
            'fastapi':      'Python/FastAPI',
            'laravel':      'PHP/Laravel',
            'symfony':      'PHP/Symfony',
            'rails':        'Ruby on Rails',
            'spring':       'Java/Spring',
            'quarkus':      'Java/Quarkus',
            'asp.net':      'ASP.NET',
            'nginx':        'nginx',
            'apache':       'Apache',
            'cloudflare':   'Cloudflare',
        }

     
        self.SENSITIVE_FIELDS = [
            'role', 'roles', 'admin', 'is_admin', 'isAdmin',
            'permission', 'permissions', 'scope', 'scopes',
            'token', 'access_token', 'refresh_token', 'jwt',
            'password', 'passwd', 'secret', 'api_key',
            'balance', 'credits', 'discount',
            'verified', 'active', 'enabled',
            'email', 'phone', 'address',
            'id', 'uid', 'uuid', 'user_id',
        ]

    def _extract_path_params(self, path: str) -> list:
        params = []
        for pattern in self.PATH_PARAM_PATTERNS:
            matches = re.findall(pattern, path)
            params.extend([m for m in matches if m])
        return list(set(params))

    def _detect_technology(self, headers: dict) -> list:
        hints = []
        combined = " ".join([
            headers.get('Server', ''),
            headers.get('X-Powered-By', ''),
            headers.get('X-Framework', ''),
            headers.get('Via', ''),
        ]).lower()

        for sig, tech in self.TECH_SIGNATURES.items():
            if sig in combined:
                hints.append(tech)

        # Cookie detection
        cookies = headers.get('Set-Cookie', '').lower()
        if 'laravel_session' in cookies:
            hints.append('PHP/Laravel')
        if 'csrftoken' in cookies:
            hints.append('Python/Django')
        if 'phpsessid' in cookies:
            hints.append('PHP')
        if 'rack.session' in cookies:
            hints.append('Ruby/Rack')

        return list(set(hints))

    def _analyze_response_schema(self, body: str) -> dict:
        result = {
            "keys": [],
            "sensitive_fields": [],
            "is_array": False,
            "is_paginated": False,
            "nested_objects": [],
        }

        try:
            parsed = json.loads(body)

            if isinstance(parsed, list):
                result["is_array"] = True
                parsed = parsed[0] if parsed else {}

            if isinstance(parsed, dict):
                result["keys"] = list(parsed.keys())

                pagination_keys = ['page', 'total', 'limit', 'offset', 'next', 'previous', 'cursor']
                if any(k in result["keys"] for k in pagination_keys):
                    result["is_paginated"] = True

                for key in result["keys"]:
                    if key.lower() in [f.lower() for f in self.SENSITIVE_FIELDS]:
                        result["sensitive_fields"].append(key)

                for key, val in parsed.items():
                    if isinstance(val, dict):
                        result["nested_objects"].append(key)

        except (json.JSONDecodeError, TypeError, IndexError):
            pass

        return result

    def _detect_auth_mechanism(self, headers: dict, status_code: int) -> dict:
        auth_info = {
            "required": False,
            "type": None,
        }

        if status_code in [401, 403]:
            auth_info["required"] = True

            www_auth = headers.get('WWW-Authenticate', '').lower()
            if 'bearer' in www_auth:
                auth_info["type"] = "JWT/Bearer"
            elif 'basic' in www_auth:
                auth_info["type"] = "Basic Auth"
            elif 'digest' in www_auth:
                auth_info["type"] = "Digest Auth"
            elif 'apikey' in www_auth or 'api-key' in www_auth:
                auth_info["type"] = "API Key"
            else:
                auth_info["type"] = "Unknown"

        return auth_info

    def _detect_content_types(self, headers: dict) -> dict:
        return {
            "accepts": headers.get('Accept', '*/*'),
            "returns": headers.get('Content-Type', 'unknown'),
        }

    def _score_attack_surface(self, intel: dict) -> tuple[int, list]:
        score = 0
        reasons = []

        if intel["path_params"]:
            score += 2
            reasons.append(f"Path params detected: {intel['path_params']}")

        if intel["auth"]["required"]:
            score += 1
            reasons.append(f"Auth required ({intel['auth']['type']}) — bypass worth testing")

        if intel["method"] in ['POST', 'PUT', 'PATCH']:
            score += 2
            reasons.append(f"{intel['method']} accepts body — injection surface")

        if intel["schema"]["sensitive_fields"]:
            score += 2
            reasons.append(f"Sensitive fields in response: {intel['schema']['sensitive_fields']}")

        if intel["schema"]["nested_objects"]:
            score += 1
            reasons.append(f"Nested objects — mass assignment possible")

        if intel["schema"]["is_paginated"]:
            score += 1
            reasons.append("Paginated response — IDOR via offset/limit")

        if intel["technology_hints"]:
            score += 1
            reasons.append(f"Tech stack identified: {intel['technology_hints']}")

        return score, reasons

    def inspect(self, method: str, path: str, verbose: bool = True) -> dict:
        intel = {
            "method": method,
            "path": path,
            "path_params": self._extract_path_params(path),
            "auth": {"required": False, "type": None},
            "schema": {"keys": [], "sensitive_fields": [], "is_array": False,
                       "is_paginated": False, "nested_objects": []},
            "technology_hints": [],
            "content_types": {},
            "options_methods": [],
            "attack_surface_score": 0,
            "attack_surface_reasons": [],
            "should_fuzz": False,
        }

        try:
            _, opt_headers, _, _ = self.client.send_request('OPTIONS', path, {})
            if 'Allow' in opt_headers:
                intel["options_methods"] = [m.strip() for m in opt_headers['Allow'].split(',')]
            intel["technology_hints"].extend(self._detect_technology(opt_headers))
        except Exception:
            pass

        try:
            status, headers, body, duration_ms = self.client.send_request(method, path, {})

            intel["auth"]             = self._detect_auth_mechanism(headers, status)
            intel["schema"]           = self._analyze_response_schema(body)
            intel["content_types"]    = self._detect_content_types(headers)
            intel["technology_hints"].extend(self._detect_technology(headers))
            intel["technology_hints"] = list(set(intel["technology_hints"]))
            intel["response_status"]  = status
            intel["response_time_ms"] = duration_ms

        except Exception as e:
            intel["error"] = str(e)

        score, reasons = self._score_attack_surface(intel)
        intel["attack_surface_score"]   = score
        intel["attack_surface_reasons"] = reasons
        intel["should_fuzz"]            = score > 0

        if verbose:
            self._print_intel(intel)

        return intel

    def _print_intel(self, intel: dict):
        score = intel["attack_surface_score"]
        score_color = Fore.GREEN if score >= 4 else (Fore.YELLOW if score >= 2 else Fore.RED)

        print(f"\n{Fore.CYAN}  ┌─ INSPECTION: {intel['method']} {intel['path']}")
        print(f"  ├─ Status       : {intel.get('response_status', 'N/A')} "
              f"({intel.get('response_time_ms', 0):.1f}ms)")
        print(f"  ├─ Auth         : {Fore.YELLOW if intel['auth']['required'] else Fore.GREEN}"
              f"{'Required — ' + intel['auth']['type'] if intel['auth']['required'] else 'None'}{Fore.CYAN}")
        print(f"  ├─ Technology   : {', '.join(intel['technology_hints']) or 'Unknown'}")
        print(f"  ├─ Path params  : {intel['path_params'] or 'None'}")
        print(f"  ├─ Schema keys  : {intel['schema']['keys'] or 'Empty'}")

        if intel['schema']['sensitive_fields']:
            print(f"  ├─ {Fore.RED}Sensitive fields: {intel['schema']['sensitive_fields']}{Fore.CYAN}")

        if intel['schema']['nested_objects']:
            print(f"  ├─ Nested objs  : {intel['schema']['nested_objects']}")

        print(f"  ├─ Content-Type : {intel['content_types'].get('returns', 'unknown')}")

        if intel['options_methods']:
            print(f"  ├─ Allow        : {', '.join(intel['options_methods'])}")

        print(f"  ├─ Attack Score : {score_color}{score}/10{Fore.CYAN}")

        for reason in intel['attack_surface_reasons']:
            print(f"  │    {Fore.YELLOW}→ {reason}{Fore.CYAN}")

        verdict = "FUZZ IT" if intel['should_fuzz'] else "SKIP"
        verdict_color = Fore.GREEN if intel['should_fuzz'] else Fore.RED
        print(f"  └─ Verdict      : {verdict_color}{verdict}{Style.RESET_ALL}")

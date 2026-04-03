import json
import re
from colorama import Fore, Style


class IDORDetector:
    def __init__(self, client):
        self.client = client

    def _diff_responses(self, body_a: str, body_b: str) -> dict:
        """
        Compare a return the differences between bodies
        """
        result = {
            "length_diff"    : abs(len(body_a) - len(body_b)),
            "identical"      : body_a == body_b,
            "fields_changed" : [],
        }

        try:
            json_a = json.loads(body_a)
            json_b = json.loads(body_b)

            if isinstance(json_a, dict) and isinstance(json_b, dict):
                for key in set(list(json_a.keys()) + list(json_b.keys())):
                    val_a = json_a.get(key)
                    val_b = json_b.get(key)
                    if val_a != val_b:
                        result["fields_changed"].append({
                            "field"  : key,
                            "own"    : val_a,
                            "other"  : val_b,
                        })
        except (json.JSONDecodeError, TypeError):
            pass

        return result

    def _extract_ids_from_response(self, body: str) -> list:
        """
        Exrtact numeric IDs and UUIDs from response
        """
        ids = []
        try:
            parsed = json.loads(body)
            flat   = json.dumps(parsed)

  
            ids.extend(re.findall(r'(?<!")\b(\d{1,10})\b', flat))
            # UUIDs
            ids.extend(re.findall(
                r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                flat, re.IGNORECASE
            ))
        except (json.JSONDecodeError, TypeError):
            pass

        return list(set(ids))

    def detect(self, method: str, path: str, intel: dict,
               reporter, verbose: bool = False) -> int:
        """
        Estrategia de detección en 3 fases:
        1. Baseline — request legítimo
        2. ID tampering — modificar IDs del path
        3. Diff — comparar responses
        """
        findings = 0

        if not intel["path_params"]:
            return findings

        for param in intel["path_params"]:

            print(f"\n{Fore.CYAN}  ┌─ IDOR CHECK: '{param}' in {method} {path}")

            status_base, _, body_base, ms_base = self.client.send_request(method, path, {})

            if status_base not in [200, 201]:
                print(f"  └─ {Fore.YELLOW}Baseline {status_base} — skipping{Style.RESET_ALL}")
                continue

            print(f"  ├─ Baseline     : {status_base} ({ms_base:.1f}ms) "
                  f"len={len(body_base)}")

            # Extraer IDs reales del response para usarlos como referencia
            real_ids = self._extract_ids_from_response(body_base)
            print(f"  ├─ IDs found    : {real_ids[:5]}")  # máximo 5 en display

            # ── FASE 2: ID tampering ──────────────────────────────────
            test_ids = [
                "0", "1", "2", "99999",          # numéricos básicos
                "-1",                             # negativo
                "null", "undefined",              # null types
                "me", "self",                     # alias
                "../1", "1%2e%2e%2f2",           # path traversal encoded
                "00000000-0000-0000-0000-000000000000",  # UUID nulo
            ]

            # Agregar IDs reales extraídos +1 y -1
            for rid in real_ids[:3]:
                try:
                    test_ids.append(str(int(rid) + 1))
                    test_ids.append(str(int(rid) - 1))
                except ValueError:
                    pass

            confirmed_idors = []

            for test_id in test_ids:
                fuzz_path = re.sub(
                    rf'\{{{param}\}}|:({param})|<[^>]*{param}[^>]*>',
                    test_id, path
                )

                status_test, _, body_test, ms_test = self.client.send_request(
                    method, fuzz_path, {}
                )

                # ── FASE 3: Diff ──────────────────────────────────────
                diff = self._diff_responses(body_base, body_test)

                # Criterios de confirmación IDOR
                is_idor = False
                reason  = ""

                if status_test == 200 and not diff["identical"]:
                    if diff["fields_changed"]:
                        is_idor = True
                        reason  = f"Different data returned for ID={test_id}"
                    elif diff["length_diff"] > 50:
                        is_idor = True
                        reason  = f"Response length diff={diff['length_diff']} for ID={test_id}"

                # 200 donde debería ser 404 — acceso no autorizado
                if status_test == 200 and status_base == 404:
                    is_idor = True
                    reason  = f"Got 200 for ID={test_id} where baseline was 404"

                if verbose:
                    status_color = Fore.GREEN if status_test == 200 else Fore.YELLOW
                    idor_flag    = f" {Fore.RED}⚡ IDOR{Style.RESET_ALL}" if is_idor else ""
                    print(f"  │  [{test_id:<40}] "
                          f"{status_color}{status_test}{Style.RESET_ALL} "
                          f"{ms_test:>7.1f}ms  "
                          f"Δlen={diff['length_diff']:<6}"
                          f"{idor_flag}")

                if is_idor:
                    findings += 1
                    confirmed_idors.append(test_id)
                    reporter.add_finding(
                        method, fuzz_path,
                        {"param": param, "id_tested": test_id},
                        f"IDOR: {reason}. Fields changed: {diff['fields_changed'][:3]}",
                        body_test,
                        "critical"
                    )
                    print(f"\n  {Fore.RED}┌─ [CRITICAL] IDOR CONFIRMED")
                    print(f"  ├─ Path      : {fuzz_path}")
                    print(f"  ├─ ID tested : {test_id}")
                    print(f"  ├─ Reason    : {reason}")
                    if diff["fields_changed"]:
                        print(f"  ├─ Changed   :")
                        for f in diff["fields_changed"][:5]:
                            print(f"  │    {f['field']}: {f['own']} → {f['other']}")
                    print(f"  └─ Snippet   : {body_test[:100]!r}{Style.RESET_ALL}\n")

            # Summary por param
            print(f"  ├─ Tested IDs  : {len(test_ids)}")
            print(f"  └─ IDOR found  : "
                  f"{Fore.RED if confirmed_idors else Fore.GREEN}"
                  f"{len(confirmed_idors)}"
                  f"{f' → {confirmed_idors}' if confirmed_idors else ' — clean'}"
                  f"{Style.RESET_ALL}")

        return findings

class BOLADetector:
    def __init__(self, client_a, client_b=None):
        self.client_a = client_a
        self.client_b = client_b

    def _get_deep_diff(self, obj_a, obj_b):
        if type(obj_a) != type(obj_b): return True
        if isinstance(obj_a, dict):
            noise_keys = {"timestamp", "time", "date", "nonce", "request_id", "id", "uuid"}
            for k in set(obj_a.keys()) | set(obj_b.keys()):
                if k.lower() in noise_keys: continue
                if k not in obj_a or k not in obj_b: return True
                if self._get_deep_diff(obj_a[k], obj_b[k]): return True
        elif isinstance(obj_a, list):
            if len(obj_a) != len(obj_b): return True
            for i in range(len(obj_a)):
                if self._get_deep_diff(obj_a[i], obj_b[i]): return True
        else:
            return obj_a != obj_b
        return False

    def detect(self, method: str, path: str, intel: dict, reporter, verbose: bool = True) -> int:
        findings = 0
        if not intel.get("path_params"):
            return 0

        for param in intel["path_params"]:
            print(f"\n{Fore.CYAN}🚀 Testing BOLA on parameter: '{param}' in {method} {path}")

            test_ids = ["1", "2", "100", "0", "9999"]
            if self.client_b:
                _, _, body_b, _ = self.client_b.send_request(method, path, {})
                extracted = re.findall(r'\b[0-9a-fA-F-]{8,36}\b|\b\d{1,8}\b', body_b)
                if extracted:
                    test_ids = list(set(extracted + test_ids))

            for t_id in test_ids:
                fuzz_path = path.replace(f"{{{param}}}", str(t_id))
                status, _, body, ms = self.client_a.send_request(method, fuzz_path, {})


                is_bola = False
                reason = ""
                
                try:
                    res_json = json.loads(body)
                    if isinstance(res_json, (dict, list)) and len(str(res_json)) > 20:
                        if status in [200, 201] and "error" not in str(res_json).lower():
                            is_bola = True
                            reason = "Success status with data-heavy JSON body"
                except:
        
                    if status == 200 and len(body) > 150:
                        is_bola = True
                        reason = "Success status with large non-JSON body"

                if verbose:
                    status_color = Fore.GREEN if status < 300 else Fore.YELLOW if status < 500 else Fore.RED
                    mark = f"{Fore.RED}[!] BOLA?{Style.RESET_ALL}" if is_bola else f"{Fore.WHITE}[-]"
                    
                    print(f"  {mark} ID: {t_id:<12} | Status: {status_color}{status}{Style.RESET_ALL} | "
                          f"Size: {len(body):<6} | Time: {ms:.1f}ms")

                if is_bola:
                    findings += 1
                    print(f"      {Fore.MAGENTA}↳ REASON: {reason}")
                    reporter.add_finding(method, fuzz_path, {"id": t_id}, reason, body, "High")

        print(f"\n{Fore.CYAN}✅ Scan completed. Findings: {findings}")
        return findings

class MassAssignmentDetector:
    def __init__(self, client):
        self.client = client

        self.PRIVILEGE_FIELDS = {
            "role"            : ["admin", "superuser", "root", "moderator"],
            "roles"           : [["admin"], ["superuser"]],
            "is_admin"        : [True, "true", "1"],
            "isAdmin"         : [True, "true", "1"],
            "admin"           : [True, "true", "1"],
            "verified"        : [True, "true", "1"],
            "email_verified"  : [True, "true", "1"],
            "active"          : [True, "true", "1"],
            "enabled"         : [True, "true", "1"],
            "permissions"     : [["admin", "write", "delete"], ["*"]],
            "scope"           : ["admin", "*", "root"],
            "balance"         : [99999, "99999"],
            "credits"         : [99999, "99999"],
            "discount"        : [100, "100"],
            "plan"            : ["premium", "enterprise", "unlimited"],
        }

    def _diff_responses(self, body_before: str, body_after: str) -> dict:
      
        result = {
            "identical"      : body_before == body_after,
            "fields_changed" : [],
            "fields_injected": [],  
        }

        try:
            json_before = json.loads(body_before)
            json_after  = json.loads(body_after)

            if not (isinstance(json_before, dict) and isinstance(json_after, dict)):
                return result

            all_keys = set(list(json_before.keys()) + list(json_after.keys()))

            for key in all_keys:
                val_before = json_before.get(key)
                val_after  = json_after.get(key)

                if val_before != val_after:
                    result["fields_changed"].append({
                        "field"  : key,
                        "before" : val_before,
                        "after"  : val_after,
                    })

             
                if key not in json_before and key in json_after:
                    result["fields_injected"].append(key)

        except (json.JSONDecodeError, TypeError):
            pass

        return result

    def _confirm_assignment(self, field: str, injected_value, response_body: str) -> tuple[bool, str]:
  
        try:
            parsed = json.loads(response_body)
            if not isinstance(parsed, dict):
                return False, ""

          
            flat = json.dumps(parsed).lower()
            val_str = str(injected_value).lower()

            if field.lower() in flat and val_str in flat:
                actual = parsed.get(field) or parsed.get(field.lower())
                return True, f"Field '{field}' reflected in response with value: {actual}"

        except (json.JSONDecodeError, TypeError):
            pass

        return False, ""

    def detect(self, method: str, path: str, intel: dict,
               reporter, verbose: bool = False) -> int:

        if method not in ['POST', 'PUT', 'PATCH']:
            return 0

        findings = 0

        print(f"\n{Fore.CYAN}  ┌─ MASS ASSIGNMENT CHECK: {method} {path}")

     
        status_base, _, body_base, ms_base = self.client.send_request(method, path, {})
        print(f"  ├─ Baseline     : {status_base} ({ms_base:.1f}ms) len={len(body_base)}")

        if status_base not in [200, 201]:
            print(f"  └─ {Fore.YELLOW}Baseline {status_base} — skipping{Style.RESET_ALL}")
            return 0

  
        schema_keys = intel["schema"]["keys"]
        print(f"  ├─ Schema keys  : {schema_keys}")

        
        priority_fields = {
            k: v for k, v in self.PRIVILEGE_FIELDS.items()
            if k in schema_keys or k.lower() in [s.lower() for s in schema_keys]
        }
        remaining_fields = {
            k: v for k, v in self.PRIVILEGE_FIELDS.items()
            if k not in priority_fields
        }

        all_fields = {**priority_fields, **remaining_fields}
        confirmed  = []

        print(f"  ├─ Priority fields : {Fore.YELLOW}{list(priority_fields.keys())}{Fore.CYAN}")
        print(f"  ├─ Testing fields  : {len(all_fields)} total{Style.RESET_ALL}\n")

        for field, test_values in all_fields.items():
            for value in test_values:

                payload = {field: value}

             
                if schema_keys:
                    for key in schema_keys[:2]:
                        if key not in payload:
                            payload[key] = "test"

                status_test, _, body_test, ms_test = self.client.send_request(
                    method, path, payload
                )

                diff      = self._diff_responses(body_base, body_test)
                confirmed_flag, confirm_reason = self._confirm_assignment(
                    field, value, body_test
                )

            
                is_vuln = False
                reason  = ""

                if confirmed_flag:
                    is_vuln = True
                    reason  = confirm_reason

                elif diff["fields_changed"]:
                 
                    for change in diff["fields_changed"]:
                        if change["field"].lower() in [f.lower() for f in self.PRIVILEGE_FIELDS]:
                            is_vuln = True
                            reason  = (f"Privilege field '{change['field']}' changed: "
                                       f"{change['before']} → {change['after']}")
                            break

                elif diff["fields_injected"]:
                    is_vuln = True
                    reason  = f"New fields appeared in response: {diff['fields_injected']}"

                if verbose:
                    status_color  = Fore.GREEN if status_test < 400 else Fore.YELLOW
                    vuln_flag     = f" {Fore.RED}⚡ VULN{Style.RESET_ALL}" if is_vuln else ""
                    value_preview = str(value)[:20]
                    print(f"  {Fore.WHITE}[TEST] {field:<20} = {value_preview:<20} "
                          f"{status_color}{status_test}{Style.RESET_ALL} "
                          f"{ms_test:>7.1f}ms"
                          f"{vuln_flag}")

                if is_vuln:
                    findings += 1
                    confirmed.append((field, value))
                    severity = "critical" if field in ['role', 'is_admin', 'isAdmin', 'permissions'] else "high"

                    reporter.add_finding(
                        method, path,
                        {"field": field, "injected_value": value},
                        f"Mass Assignment: {reason}",
                        body_test,
                        severity
                    )

                    print(f"\n  {Fore.RED}┌─ [{severity.upper()}] MASS ASSIGNMENT CONFIRMED")
                    print(f"  ├─ Field    : {field}")
                    print(f"  ├─ Injected : {value}")
                    print(f"  ├─ Reason   : {reason}")
                    if diff["fields_changed"]:
                        print(f"  ├─ Changes  :")
                        for c in diff["fields_changed"][:4]:
                            print(f"  │    {c['field']}: {c['before']} → {c['after']}")
                    print(f"  └─ Snippet  : {body_test[:120]!r}{Style.RESET_ALL}\n")

       
        result_color = Fore.RED if confirmed else Fore.GREEN
        print(f"\n  {Fore.CYAN}┌─ MASS ASSIGNMENT SUMMARY {method} {path}")
        print(f"  ├─ Fields tested : {len(all_fields)}")
        print(f"  ├─ Confirmed     : {result_color}{len(confirmed)}{Fore.CYAN}")
        if confirmed:
            for field, value in confirmed:
                print(f"  │    {Fore.RED}→ {field} = {value}{Fore.CYAN}")
        print(f"  └─ Verdict       : "
              f"{Fore.RED + 'VULNERABLE' if confirmed else Fore.GREEN + 'CLEAN'}"
              f"{Style.RESET_ALL}")

        return findings
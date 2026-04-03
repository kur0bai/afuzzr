class Fields():
    SENSITIVE_FIELDS = ["role", "admin", "privilege", "owner", "internal"]
    PII_PATTERNS = ["email", "phone", "address", "birthday", "token", "password_hash"]
    DOCUMENTATION_PATHS = ["openapi.json", "swagger.json", "swagger-ui", 
        "api-docs", "redoc", ".yaml", ".yml", "/docs"]
    HMTL_CRITICAL_PATTERNS = ["BEGIN RSA PRIVATE KEY", "access_key_id", "session_id"]
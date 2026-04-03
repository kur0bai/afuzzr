import requests
import time
import random
import urllib3
from typing import Dict, Any, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
]

class FuzzerHttpClient:
    def __init__(self, base_url: str, delay: float = 0.2, stealth: bool = False):
        self.base_url   = base_url.rstrip('/')
        self.session    = requests.Session()
        self.delay      = delay
        self.stealth    = stealth

        self._set_base_headers()

    def _set_base_headers(self):
        self.session.headers.update({
            "User-Agent"      : random.choice(USER_AGENTS),
            "Accept"          : random.choice(ACCEPT_HEADERS),
            "Accept-Language" : "en-US,en;q=0.9",
            "Accept-Encoding" : "gzip, deflate, br",
            "Connection"      : "keep-alive",
        })

    def _get_delay(self) -> float:
        if self.stealth:
            # Delay personating human behavior
            jitter = random.uniform(-self.delay * 0.4, self.delay * 1.5)
            return max(0.1, self.delay + jitter)
        return self.delay

    def _build_request_kwargs(self, method: str, payload: Dict[str, Any]) -> dict:
        kwargs = {"timeout": 15, "verify": False}

        if not payload:
            return kwargs

        if method == "GET":
            kwargs["params"] = payload
        else:
            # Alternate between json and form-data 
            if self.stealth and random.random() < 0.3:
                kwargs["data"] = payload 
            else:
                kwargs["json"] = payload  

        return kwargs
    

    def set_auth_token(self, token: str):
        """Actualiza el token de portador para esta sesión."""
        # Detecta si ya trae el prefijo Bearer o es solo el string
        auth_value = token if token.lower().startswith(("bearer ", "basic ")) else f"Bearer {token}"
        self.session.headers.update({"Authorization": auth_value})    

    def send_request(
        self,
        method: str,
        path: str,
        payload: Any = None,
        custom_headers: Dict = None
    ) -> Tuple[int, Dict, str, float]:
        """
        Envía peticiones con lógica de auditoría.
        Payload puede ser Dict (JSON/Params) o String (Raw).
        """
        full_url = f"{self.base_url}{path}"
        
        # Rotación de headers en modo sigilo
        if self.stealth:
            self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

        # Preparar kwargs
        kwargs = {"timeout": 15, "verify": False, "headers": custom_headers}
        
        if payload is not None:
            if method.upper() == "GET":
                kwargs["params"] = payload
            else:
                # Si es un dict, enviamos JSON (estándar de API moderna)
                # Si no, enviamos data (raw o form)
                if isinstance(payload, dict):
                    kwargs["json"] = payload
                else:
                    kwargs["data"] = payload

        time.sleep(self._get_delay())
        start_time = time.time()

        try:
            response = self.session.request(method.upper(), full_url, **kwargs)
            duration_ms = (time.time() - start_time) * 1000
            
            return response.status_code, dict(response.headers), response.text, duration_ms

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return 0, {}, f"Request Error: {str(e)}", duration_ms
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
                kwargs["data"] = payload   # form-data
            else:
                kwargs["json"] = payload   # json body

        return kwargs

    def send_request(
        self,
        method: str,
        path: str,
        payload: Dict[str, Any]
    ) -> Tuple[int, Dict, str, float]:

        full_url = f"{self.base_url}{path}"

        # Rotate headers
        if self.stealth:
            self.session.headers.update({
                "User-Agent" : random.choice(USER_AGENTS),
                "Accept"     : random.choice(ACCEPT_HEADERS),
            })

        delay = self._get_delay()
        time.sleep(delay)

        kwargs = self._build_request_kwargs(method, payload)

        start_time = time.time()
        try:
            response = self.session.request(method, full_url, **kwargs)
            duration_ms = (time.time() - start_time) * 1000
            return response.status_code, dict(response.headers), response.text, duration_ms

        except requests.exceptions.ConnectionError as e:
            duration_ms = (time.time() - start_time) * 1000
            return 0, {}, f"ConnectionError: {e}", duration_ms

        except requests.exceptions.Timeout:
            duration_ms = (time.time() - start_time) * 1000
            return 0, {}, "Timeout", duration_ms

        except requests.exceptions.RequestException as e:
            duration_ms = (time.time() - start_time) * 1000
            return 0, {}, f"RequestException: {e}", duration_ms
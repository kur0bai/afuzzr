import requests
import time
from typing import Dict, Any, Tuple

class FuzzerHttpClient():
    def __init__(self, base_url: str, delay: float = 0.1) -> None:
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.delay = delay

        # Updating headers to simulate a firefoxb browser
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
        })

    """
        Basic function to handle all the http requests in a dynamic way
    """

    def send_request(self, method: str, path: str, payload: Dict[str, Any], params: Dict = None) -> Tuple[int, Dict, str]:
        full_url = f"{self.base_url}{path}"

        try:
            time.sleep(self.delay)
            response = self.session.request(method, full_url, json=payload, params=params, timeout=10, verify=False)
            return response.status_code, response.headers, response.text
        except requests.exceptions.RequestException as ex:
            return 0, {}, str(ex)
import sys
import yaml
import json
from colorama import Fore, Style

class Utils():
    def load_openapi_spec(self, file_path: str) -> dict:
        """
        Just open the path of specs if specified
        """
        try:
            with open(file_path, 'r') as f:
                if file_path.endswith('.yaml') or file_path.endswith('.yml'):
                    return yaml.safe_load(f)
                return json.load(f)
        except Exception as ex:
            print(f"{Fore.RED}[✘]{Style.RESET_ALL} Unexpected error loading specs: {ex}")
            sys.exit(1)        


    def load_wordlist(self, file_path: str) -> list:
        """
        Open wordlist based on path
        """
        try:
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[✘]{Style.RESET_ALL} File not found: '{file_path}'")
            sys.exit(1)
        except PermissionError:
            print(f"{Fore.RED}[✘]{Style.RESET_ALL} Permission denied: '{file_path}'")
            sys.exit(1)
        except Exception as ex:
            print(f"{Fore.RED}[✘]{Style.RESET_ALL} Unexpected error loading wordlist: {ex}")
            sys.exit(1)
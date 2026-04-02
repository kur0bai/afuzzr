import argparse
import sys
from colorama import Fore, Style, init
from core.http_client import FuzzerHttpClient
from core.payload_generator import PayloadGenerator
from core.reporter import Reporter
from core.fuzzer import Fuzzer
from utils.file import Utils

init(autoreset=True)


def show_banner():
    """
    Main identifier banner
    """  
    banner = [
        "\n\n",                                                           
        (Fore.CYAN + r"           /$$$$$$                                        " ),
        (Fore.CYAN + r"          /$$__  $$                                       " ),
        (Fore.CYAN + r" /$$$$$$ | $$  \__//$$   /$$ /$$$$$$$$ /$$$$$$$$  /$$$$$$" ),
        (Fore.CYAN + r"|____  $$| $$$$   | $$  | $$|____ /$$/|____ /$$/ /$$__  $$" ),
        (Fore.CYAN + r" /$$$$$$$| $$_/   | $$  | $$   /$$$$/    /$$$$/ | $$  \__/" ),
        (Fore.CYAN + r"/$$__  $$| $$     | $$  | $$  /$$__/    /$$__/  | $$      " ),
        (Fore.CYAN + r"|  $$$$$$$| $$     |  $$$$$$/ /$$$$$$$$ /$$$$$$$$| $$     " ),
        (Fore.CYAN + r" \_______/|__/      \______/ |________/|________/|__/     " ),
        (Fore.CYAN + r""),
        (Fore.CYAN + r"Author: " + Fore.WHITE + r"kur0bai" ),
        (Fore.CYAN + r"Visit: " + Fore.WHITE + r"https://github.com/kur0bai"),
        Style.RESET_ALL
    ]

    for line in banner:
        print(line)




def get_args():
    """
    Get Menu list of params
    """
    parser = argparse.ArgumentParser(
    prog="api-fuzzer",
    description=f"{Fore.CYAN}afuzzr - Simple and fast tool for discovering API endpoints{Style.RESET_ALL}",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=f"""
    {Fore.YELLOW}Examples:{Style.RESET_ALL}
    python afuzzr.py --url https://api.target.com --wordlist wordlists/api-endpoints.txt
    python afuzzr.py --url https://api.target.com --mode spec --spec openapi.json --success
    python afuzzr.py --url https://api.target.com --wordlist endpoints.txt --stealth -vvv
    """
    )
    parser.add_argument("--url", type=str,
                    required=True,
                    help="Target base URL to fuzz (e.g. https://api.example.com)")
    parser.add_argument("--spec", type=str,
                    required=False,
                    help="Path to OpenAPI/Swagger file (openapi.json or swagger.json). Used only with --mode spec")
    parser.add_argument("--mode", "-m", choices=['spec', 'dict'], default="dict",
                    help="Fuzzing mode: 'dict' (wordlist) or 'spec' (parse from OpenAPI file)")
    parser.add_argument("--wordlist", "-w", type=str,
                    required=False,
                    help="Path to the wordlist/dictionary file containing endpoints to fuzz (required in 'dict' mode)")
    parser.add_argument("--stealth", "-s", action="store_true",
                    help="Enable stealth mode (random delays + basic WAF evasion techniques)")
    parser.add_argument("--verbose", "-vvv", action="store_true",
                    help="Enable verbose output (shows detailed information for each request)")
    # Recommended practical filter
    parser.add_argument("--success", action="store_true",
                    help="Show only successful responses (status codes 200 and 403). Recommended to reduce noise.")                                               
    args = parser.parse_args()
    return args


def main():
    show_banner()
    args = get_args()
    base_url = args.url
    spec_path = args.spec
    mode = args.mode
    wordlist = args.wordlist
    stealth = args.stealth
    verbose = args.verbose
    success = args.success

    try:
        print(f"{Fore.WHITE}[•] Stealth Mode {Fore.CYAN}ENABLED{Fore.WHITE}") if stealth else print(f"{Fore.WHITE}[•] Stealth Mode {Fore.YELLOW}DISABLED{Fore.WHITE}")

        delay = 0.1 if stealth else 0.2

        client = FuzzerHttpClient(base_url, delay, stealth)
        generator = PayloadGenerator()
        reporter = Reporter()

        fuzzer = Fuzzer()
        utils = Utils()

        if mode == 'dict':
            fuzzer.fuzz_with_dict(base_url, client, generator, reporter, wordlist, verbose, success)
        elif mode == 'spec':
            if not spec_path:
                print(f"{Fore.RED}[!] Error: The 'spec' mode requires the argument --spec.")
                return
            spec = utils.load_openapi_spec(spec_path)
            fuzzer.fuzz_with_spec(spec, base_url, client, generator, reporter)


        print(f"\n{Fore.GREEN}[•] Fuzzing completed.")
        reporter.save_report('fuzzer_report.html')
    except KeyboardInterrupt as ex:
        print(f"\n\n{Fore.RED}[!] Ctrl+C detected. Exiting")
        sys.exit(0)    

if __name__ == "__main__":
    main()

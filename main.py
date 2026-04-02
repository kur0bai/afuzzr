import argparse
import sys
from colorama import Fore, Style, init
from core.http_client import FuzzerHttpClient
from payload_generator import PayloadGenerator
from reporter import Reporter
from fuzzer import Fuzzer
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
    parser = argparse.ArgumentParser(description="Easy way to fuzz APIs")
    parser.add_argument("--url", type=str,
                        required=True,
                        help="The Target URL to fuzz")
    parser.add_argument("--spec", type=str, 
                        required=False, 
                        help="The openapi.json file (Optional)")
    parser.add_argument("--m", choices=['spec', 'dict'],
                        required=False, help="Mode", default="dict")
    parser.add_argument("--w", "--wordlist", 
                    required=False, 
                    help="Wordlist dictionary path to FUZZ")
    parser.add_argument("-s", "--stealth", 
                    action="store_true", 
                    required=False, 
                    help="Enable stealth mode (Delay and WAF evasion)")
    parser.add_argument("-vvv", action="store_true", required=False, help="Enabling verbose")                                                     
    args = parser.parse_args()
    return args


def main():
    show_banner()
    args = get_args()
    base_url = args.url
    spec_path = args.spec
    mode = args.m
    wordlist = args.w
    stealth = args.stealth
    verbose = args.vvv

    try:
        print(f"{Fore.WHITE}[•] Stealth Mode {Fore.CYAN}ENABLED{Fore.WHITE}") if stealth else print(f"{Fore.WHITE}[•] Stealth Mode {Fore.YELLOW}DISABLED{Fore.WHITE}")

        delay = 0.1 if stealth else 0.2

        client = FuzzerHttpClient(base_url, delay, stealth)
        generator = PayloadGenerator()
        reporter = Reporter()

        fuzzer = Fuzzer()
        utils = Utils()

        if mode == 'dict':
            fuzzer.fuzz_with_dict(base_url, client, generator, reporter, wordlist, verbose)
        elif mode == 'spec':
            if not spec_path:
                print(f"{Fore.RED}[!] Error: The 'spec' mode requires the argument --spec.")
                return
            spec = utils.load_openapi_spec(spec_path)
            fuzzer.fuzz_with_spec(spec, base_url, client, generator, reporter)


        print(f"\n{Fore.GREEN}[*] Fuzzing completed.")
        reporter.save_report('fuzzer_report.html')
    except KeyboardInterrupt as ex:
        print(f"\n\n{Fore.RED}[!] Ctrl+C detected. Exiting")
        sys.exit(0)    

if __name__ == "__main__":
    import os
    main()

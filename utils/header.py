from colorama import Fore, Style, init

class Header():
    def print_header(self, title: str, emoji: str = "⚡"):
        print(f"\n{Fore.WHITE}{Style.BRIGHT}╔" + "═" * 72 + "╗")
        print(f"║  {Fore.CYAN}{emoji}  {title.upper():<48}  {Fore.WHITE}                ║")
        print(f"╚" + "═" * 72 + f"╝{Style.RESET_ALL}")
        print()  
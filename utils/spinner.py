import sys
import threading
import time

from colorama import Fore, Style, init


class Spinner:
    """
    Function to show and hide spinner animation
    """
    init(autoreset=True)
    def __init__(self, message="Loading"):
        self.spinner = ["⢿", "⣻", "⣽", "⣾", "⣷", "⣯", "⣟", "⡿"]
        self.message = message
        self.running = False
        self.thread = None

    def start(self):
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()

        # clean
        sys.stdout.write("\r" + " " * (len(self.message) + 4) + "\r")
        sys.stdout.flush()

    def _animate(self):
        while self.running:
            for frame in self.spinner:
                if not self.running:
                    break
                sys.stdout.write(f"\r{self.message} {frame} ")
                sys.stdout.flush()
                time.sleep(0.1)  # speed

    def print_header(self, title: str, emoji: str = "⚡"):
        print(f"\n{Fore.WHITE}{Style.BRIGHT}╔" + "═" * 72 + "╗")
        print(f"║  {Fore.CYAN}{emoji}  {title.upper():<48}  {Fore.WHITE}                ║")
        print(f"╚" + "═" * 72 + f"╝{Style.RESET_ALL}")
        print()  


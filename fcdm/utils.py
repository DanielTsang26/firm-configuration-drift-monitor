from colorama import Fore, Style

def colorize(text,color):
    """
     Wraps text in the specified color and resets the style.

     Args:
      text(str): String that gets colorized
      color (colorama.Fore): Color constant (e.g., Fore.GREEN)
    Return:
    str: Colorized string.
    """
    return f"{color}{text}{Style.RESET_ALL}"
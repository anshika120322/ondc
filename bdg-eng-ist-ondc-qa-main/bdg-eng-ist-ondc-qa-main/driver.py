import sys
from datetime import datetime
from argparse import ArgumentParser
from common_test_foundation.main import main, add_custom_arguments, parse_arguments

"""
-------------------------------------------------------------------
Main file to start the CTF framework
-------------------------------------------------------------------
"""
# Here we are defining custom arguments
def setup_parser_arguments(parser: ArgumentParser):
    custom_group = parser.add_argument_group("Custom options")
    custom_group.add_argument('--arg-name', type=str, help="Help text", env_var="ENV_VAR_NAME")


def process_html_argument():
    """Intercepts and processes the --html argument to handle datetime placeholder"""
    for i, arg in enumerate(sys.argv):
        if arg == "--html" and i + 1 < len(sys.argv):
            report_path = sys.argv[i + 1]
            if "{datetime}" in report_path:
                now = datetime.now().strftime("%Y%m%d_%H%M%S")
                sys.argv[i + 1] = report_path.replace("{datetime}", now)


if __name__ == "__main__":
    """Main call of the file, starts and sets initial configuration"""
    process_html_argument()
    add_custom_arguments(function=setup_parser_arguments) # Set custom arguments to be used
    parse_arguments() # Parsing arguments and set them as globals
    main() # Main call of the framework

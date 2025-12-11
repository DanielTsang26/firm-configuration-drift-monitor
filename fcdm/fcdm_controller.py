import time
import os
import sys
import argparse
from colorama import Fore, Style
from .fcdm_extractor import FirmwareExtractor 
from .fcdm_parser import ConfigParser 
from .fcdm_policy_verifier import PolicyVerifier
from .utils import colorize

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fcdm import LOGO, __version__

def view_log():
    HOME_DIR = os.path.expanduser('~')
    log_file_path = os.path.join(HOME_DIR, 'fcdm_analysis.log')

    if os.path.exists(log_file_path):
        try:
           with open(log_file_path,'r') as f:
                content = f.read()
                if content:
                    print(content)
                else:
                    print("[INFO]:Log file is empty.")
        except Exception as e:
                  print(f"[ERROR] Could not find log file: {e}")
    else:
        print("[INFO] No log file was found during analysis.")

class ColoredTextFormatter(argparse.RawTextHelpFormatter):
    """Custom wrapper that adds color to argparse help output."""

    def _format_usage(self, usage, actions, groups, prefix):
        if prefix:
            prefix = colorize(prefix, Fore.BLUE)
        return super()._format_usage(usage,actions, groups, prefix)
    
    def _format_action(self, action):

        formatted_action = super()._format_action(action) 
        
        if action.help:
            help_start_index = formatted_action.find(action.help.strip())

            if help_start_index != -1:
                name_part_with_padding = formatted_action[:help_start_index].rstrip()
                help_part_from_start = formatted_action[help_start_index:]

                flag_start_index = len(name_part_with_padding) - len(name_part_with_padding.lstrip())
                flag_name_only = name_part_with_padding[flag_start_index:].rstrip()
                leading_padding = name_part_with_padding[:flag_start_index]
                colored_flag_name = colorize(flag_name_only, Fore.GREEN)

                colored_help_description = colorize(help_part_from_start,Fore.GREEN)

            return f"{leading_padding}{colored_flag_name} {colored_help_description}" 
        
        return colorize(formatted_action.strip(), Fore.GREEN)
    

class FCDMController:
    
    def __init__(self,parser , verifier, extractor, log_file_path = 'fcdm_analysis.log'):
        self.parser = parser
        self.verifier = verifier
        self.extractor = extractor
        self.log_file_path = log_file_path
        self.log_messages = []
    
    def log(self,message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_messages.append(f"[{timestamp}] {message}")
        print(message)
    
    def write_log(self):
        with open(self.log_file_path,'w') as f:
            f.write("\n".join(self.log_messages))
        print(f"\n[INFO] Diagnostic log written to: {self.log_file_path}")
    
  
  
    def run_auth_integrity_audit(self):
        self.log("\n---Starting FCDM Drift Analysis---")

        # ---- Extraction phase ----
        v1_root_dir = os.path.join(self.extractor.base_dir,"_firmware_v1_hardened.img.extracted", "squashfs-root")
        config_path_v1 = os.path.join(v1_root_dir, "etc","config", "dropbear")

        self.extractor.extracted_last_root = v1_root_dir
        fire_wall_path_v1 = self.extractor.get_firewall_path()

        v2_root_dir = os.path.join(self.extractor.base_dir,"_firmware_v2_drift.img.extracted", "squashfs-root")
        config_path_v2 = os.path.join(v2_root_dir, "etc","config", "dropbear")

        self.extractor.extracted_last_root = v2_root_dir
        fire_wall_path_v2 = self.extractor.get_firewall_path()

        if None in (config_path_v1, config_path_v2, fire_wall_path_v1, fire_wall_path_v2):
            self.log("Analysis Aborted: Could not extract all required configuration files.")
            self.write_log()
            return

        #--- Parsing phase ----
        config_v1 = self.parser.parse_dropbear_config(config_path_v1)
        config_v2 = self.parser.parse_dropbear_config(config_path_v2)

        net_v1 = self.parser.parse_firewall_config(fire_wall_path_v1)
        net_v2 = self.parser.parse_firewall_config(fire_wall_path_v2)
      
        if None in (config_v1, config_v2, net_v1, net_v2):
            self.log("Analysis Aborted: Could not normalize all configuration data.")
            self.write_log()
            return
        
        self.log("\n -> Running formal verification (Z3)")
        self.write_log()
        
        # ---- Verification phase ---
        verification_result = self.verifier.check_security_drift(config_v1, config_v2, net_v1, net_v2)
        self.log(verification_result)

        self.log("---FCDM Analysis Complete---")
        self.write_log()


def run_fcdm(v1_path,v2_path):

    HOME_DIR = os.path.expanduser('~')
    LOG_FILE = os.path.join(HOME_DIR, 'fcdm_analysis.log')

    print(f"\nV1 Baseline: {v1_path}")
    print(f"V2 Candidate:{v2_path}")
 

    extractor_instance =  FirmwareExtractor(base_dir = HOME_DIR) 
    parser_instance = ConfigParser()
    verifier_instance = PolicyVerifier()

    controller = FCDMController(parser = parser_instance,
                                 verifier=verifier_instance, 
                                 extractor = extractor_instance,
                                 log_file_path= LOG_FILE
                                 )
    
    controller.run_auth_integrity_audit()

def cli_cmd():
    
    core_description = (f"{Fore.GREEN}Version: {__version__}{Style.RESET_ALL}\n"
                        f"{Fore.GREEN}Firmware Configuration Drift Monitor (FCDM) is a tool for Formal Verification of Firmware Configuration Drift. "
                        f"{Style.RESET_ALL}\n"
                        )
    
    full_description = f"{Fore.GREEN}{LOGO.strip()}\n\n{core_description}"
    

    parser = argparse.ArgumentParser(prog = "Firmware Configuration Drift Monitor",
                                     formatter_class=ColoredTextFormatter,
                                    description=full_description,
                                    usage =argparse.SUPPRESS
                                    )
    # iterate through the sections ( options and positional arguments) and color them.
    for group in parser._action_groups:
        if group.title == 'positional arguments':
            group.title = colorize('positional arguments', Fore.GREEN)
        elif group.title == 'options':
            group.title = colorize('options', Fore.GREEN)

    parser.add_argument(
        '-l','--log',
        action='store_true',
        help=' view the contents of the last analysis log.'
    )

    parser.add_argument(
        'paths',
        nargs='*',
        help=' [V1_Path],[V2_Path] -Path of v1 (baseline, secure) and V2 (candidate) firmware image directories.'
    )

    parser.add_argument(
        '-V', '--version',
        action ='version',
        version='FCDM ' + __version__
    )
    
    return parser.parse_args()
    


def main():
    try:
        args = cli_cmd()

        
        if args.log:
            view_log()
            sys.exit(0)

        
        if len(args.paths) != 2:
            print("\nERROR: You must provide exactly two firmware paths for analysis.", file=sys.stderr)
            print("Usage: python fcdm_controller.py <V1_PATH> <V2_PATH>", file=sys.stderr)
            print("       python fcdm_controller.py --logs", file=sys.stderr)
            sys.exit(1)

        # Extract variables from the list 'args.path'
        v1_path = args.paths[0]
        v2_path = args.paths[1]

        
        if not os.path.isdir(v1_path) or not os.path.isdir(v2_path):
            print(f"\nERROR: Both V1 and V2 paths must be existing directories.", file=sys.stderr)
            sys.exit(1)
        
        
        run_fcdm(v1_path, v2_path)

    except KeyboardInterrupt:
        print("\n\n Analysis ended due to user pressing CTRL+C. Exiting program...")
        sys.exit(0)

    except Exception as e:
        print(f"\nAn unexpected error has occurred: {e}", file=sys.stderr)
        sys.exit(1)

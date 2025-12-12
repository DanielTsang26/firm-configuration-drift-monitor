import sys
import os
from colorama import Fore, Style



# 1. Get the directory containing the current script (e.g., /home/.../python-project/test)
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. Get the PROJECT_ROOT (go up one level: /home/.../python-project)
PROJECT_ROOT = os.path.dirname(CURRENT_DIR) 

# 3. Add the PROJECT_ROOT to sys.path. 
# This tells Python to search in /home/.../python-project for the 'fcdm' package.
sys.path.append(PROJECT_ROOT)

try:
    from fcdm.fcdm_policy_verifier import PolicyVerifier

except ImportError as e:
    print(f"{Fore.RED}FATAL ERROR:{Style.RESET_ALL} Failed to load FCDM core classes.")
    print(f"Details: {e}")
    print("\nTroubleshooting Tip: Ensure fcdm/__init__.py exists and the fcdm_parser.py/fcdm_policy_verifier.py files are directly inside the 'fcdm' folder.")
    sys.exit(1)
    

def run_test(name, config_v1, firewall_v1, config_v2, firewall_v2, expected_pass=False):
    """Executes a single test case using the PolicyVerifier."""
    print(f"\n--- Running Test Case: {name} ---")
    
    try:
        # Initialize the PolicyVerifier (it loads fcdm_config.json internally)
        verifier = PolicyVerifier()

        # Execute the check_security_drift method
        result_text = verifier.check_security_drift(
            config_v1, config_v2, firewall_v1, firewall_v2
        )
        
        # Check if a CRITICAL DRIFT was DETECTED
        drift_detected = "CRITICAL DRIFT DETECTED" in result_text
        
        if expected_pass and not drift_detected:
            print(f"{Fore.GREEN}PASS:{Style.RESET_ALL} Policy holds (as expected).")
        elif not expected_pass and drift_detected:
            print(f"{Fore.GREEN}PASS:{Style.RESET_ALL} Drift detected (as expected).")
        else:
            print(f"{Fore.RED}FAIL:{Style.RESET_ALL} Unexpected result.")

        print(result_text)

    except Exception as e:
        print(f"{Fore.RED}FAIL:{Style.RESET_ALL} Test crashed with exception: {e}")

# --- Test Case Definitions ---

# Mock configuration data representing the state extracted by the parser
# { "root_login_allowed": BOOL, "password_auth_enabled": BOOL }

# TC-08: Auth Regression Test (V1 secure -> V2 insecure)
def test_auth_regression():
    config_v1 = {"root_login_allowed": False, "password_auth_enabled": False}
    firewall_v1 = set() # No ports open
    
    config_v2 = {"root_login_allowed": True, "password_auth_enabled": False} # Regression here
    firewall_v2 = set()
    
    run_test("TC-08: Auth Regression (Root Login)", 
             config_v1, firewall_v1, config_v2, firewall_v2, expected_pass=False)

# TC-09: Network Regression Test (V1 secure -> V2 insecure)
def test_network_regression():
    config_v1 = {"root_login_allowed": False, "password_auth_enabled": False}
    firewall_v1 = set()
    
    config_v2 = {"root_login_allowed": False, "password_auth_enabled": False}
    # Assuming port '23' (Telnet) is in your fcdm_config.json's CRITICAL_PORTS
    firewall_v2 = {'23'} 
    
    run_test("TC-09: Network Regression (Port 23)", 
             config_v1, firewall_v1, config_v2, firewall_v2, expected_pass=False)

# TC-10: No Change Test (Baseline)
def test_no_change():
    config_v1 = {"root_login_allowed": False, "password_auth_enabled": False}
    firewall_v1 = set()
    
    config_v2 = {"root_login_allowed": False, "password_auth_enabled": False}
    firewall_v2 = set()
    
    run_test("TC-10: No Change (Expected Pass)", 
             config_v1, firewall_v1, config_v2, firewall_v2, expected_pass=True)

# --- Execution ---

if __name__ == "__main__":
    print(f"{Fore.CYAN}--- FCDM Policy Verification Test Suite ---{Style.RESET_ALL}")
    
    test_auth_regression()
    test_network_regression()
    test_no_change()
    
    print(f"\n{Fore.CYAN}--- Test Suite Complete ---{Style.RESET_ALL}")

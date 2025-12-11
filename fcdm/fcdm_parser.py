import json
import os


class ConfigParser:
    """Handles the configuration parsing process."""
    
    def __init__(self, default_root_allowed=False):
        self.default_root_allowed = default_root_allowed

        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(current_file_dir, 'fcdm_config.json')
        try:
            with open(config_path, 'r') as f:
                self.policy = json.load(f)
                self.CRITICAL_PORTS = self.policy['critical_ports']

        except FileNotFoundError:
            raise FileNotFoundError(f"Required configuration file 'fcdm_config.json' not found. "
                f"It must be in the same folder as the parser script. Looked at: {config_path}"
            )

        
    def parse_firewall_config(self, file_path):
        open_ports = set()
        current_rules = {}
        in_rule = False

        def check_and_add_port(rules):
            if (rules.get('src') == 'wan' and 
                rules.get('dest_port')in self.CRITICAL_PORTS and rules.get('target') == 'ACCEPT'):
                open_ports.add(rules['dest_port'])

        try: 
            with open(file_path,'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue

                    if line.startswith('config rule'):
                        check_and_add_port(current_rules)
                        current_rules = {}
                        in_rule = True

                    elif in_rule:
                        parts = line.split()
                        if len(parts) >= 3 and parts[0] == 'option':
                            key = parts[1]
                            raw_val = ' '.join(parts[2:])
                            val = raw_val.strip("'\"").strip()
                            current_rules[key] = val

            check_and_add_port(current_rules)        
            
        except FileNotFoundError:
            print(f"Warning: Firewall config not found at {file_path}.")
            return set()
        
        return open_ports
                    

    def parse_dropbear_config(self, file_path):
        """
        Parses the dropbear UCI config and normalizes policy settings.
        file_path is now correctly recognized as an argument of this method.
        """
        
        policy_settings = {
            "root_login_allowed": self.default_root_allowed,
            "password_auth_enabled": False  
        }


        in_dropbear_config = False

        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    
                    if not line or line.startswith('#'):
                        continue
                
                    if line.startswith('config dropbear'):
                        in_dropbear_config = True
                    
                    elif in_dropbear_config:
                        parts = line.split()
                        
                        if len(parts) >= 3 and parts[0].lower() == 'option':
                            directive = parts[1].lower()
                            value = parts[2].strip("'").lower()

                            if directive == 'rootpasswordauth':
                                policy_settings["root_login_allowed"] = (value == 'on')
                        
                            elif directive == 'passwordauth':
                                policy_settings["password_auth_enabled"] = (value == 'on')

        except FileNotFoundError:
            print(f"Error: Config file not found at {file_path}")
            return None
        
        return policy_settings
import subprocess
import os

class FirmwareExtractor:
    """Handles binwalk operations and file path resolution."""
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.extracted_last_root = None

    def extract_config(self, firmware_path):
        """Extracts firmware and returns the path to the dropbear config."""
        print(f"\n-> Starting extraction on: {firmware_path}")
        
        base_name = os.path.basename(firmware_path)
        output_dir_root = os.path.join(self.base_dir, f"_{base_name}.extracted")
        
        if os.path.exists(output_dir_root):
            subprocess.run(['rm', '-rf', output_dir_root], check=True)
        else:
            try:
               subprocess.run(['binwalk', '-e', firmware_path], 
                           cwd=self.base_dir, check=True, capture_output=True)
               print("-> Binwalk extraction successful.")
            except subprocess.CalledProcessError:
               print("ERROR: Binwalk failed during extraction.")
            return None

        extract_config_path = os.path.join(output_dir_root, "squashfs-root","etc","config","dropbear")
        extracted__root = os.path.join(output_dir_root, "squashfs-root")
        self.extracted_last_root = extracted__root

        
        if not os.path.exists(extract_config_path):
            print(f"ERROR: Config file not found at expected location.")
            if not os.path.exists(extracted__root):
                print("DIAGNOSIS: Squashfs-root directory was not created.")
            return None
        
        print(f"-> Configuration file located: {extract_config_path}")
        return extract_config_path
    
    def get_firewall_path(self):
        if not self.extracted_last_root:
            raise Exception("Extraction of firewall path not found.")
        
        firewall_path = os.path.join(self.extracted_last_root, "etc","config","firewall")

        if not os.path.exists(firewall_path):
            print("ERROR: Firewall config file not found at {firewall_path}.")
            return None
        
        return firewall_path
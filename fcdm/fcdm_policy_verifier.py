
from z3 import Solver, Bool, And, Or, sat , is_true
import json
import os



class PolicyVerifier:
    """Encodes the Z3 constraints as part of the security policy and mathematically analyzes the configuration drift."""
    def __init__(self):


        
        current_file_dir= os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(current_file_dir, 'fcdm_config.json')

        try:
            with open(config_path,'r') as f:    
                self.policy = json.load(f)
                self.service_port = self.policy['service_hardening']['service_port']
        except Exception as e:
            raise FileNotFoundError(f"Required configuration file fcdm_config.json"
                                    f" Ensure the file is in the 'fcdm' folder. Error: {e}")

    def check_security_drift(self, config_v1, config_v2, firewall_v1, firewall_v2):
        solver = Solver()
        auth_var_dict = {
            'v1': {
                'root_allowed': Bool('v1_root_allowed'),
                'password_enabled': Bool('v1_password_enabled')
            },
            'v2':{
                'root_allowed': Bool('v2_root_allowed'),
                'password_enabled': Bool('v2_password_enabled')
            }
        }
        
        # Examine and extract observable ports found in the firmware, then store them in a list.
        all_obs_ports = firewall_v1 | firewall_v2
        if not all_obs_ports:
            ports_to_model = []
        else:
            ports_to_model = sorted(list(all_obs_ports))

        net_var_dict = {
            'v1': {p: Bool(f'v1_{p}_open') for p in ports_to_model},
            'v2': {p: Bool(f'v2_{p}_open') for p in ports_to_model}

            }
        for version, cfg in [('v1', config_v1), ('v2', config_v2)]:
            solver.add(auth_var_dict[version]['root_allowed'] == cfg['root_login_allowed'])
            solver.add(auth_var_dict[version]['password_enabled'] ==cfg['password_auth_enabled'])
        
    
        for version, fw_ports in [('v1', firewall_v1), ('v2', firewall_v2)]:
            for p in ports_to_model:
                solver.add(net_var_dict[version][p] == (p in fw_ports))

        v1_was_secure = And(auth_var_dict['v1']['root_allowed']== False,
                            auth_var_dict['v1']['password_enabled']== False
                            )
        
        v2_is_insecure = Or(auth_var_dict['v2']['root_allowed'] == True,
                            auth_var_dict['v2']['password_enabled'] == True)
        
        security_drift_proof = And(v1_was_secure, v2_is_insecure)

        net_v1_secure = And(*(net_var_dict['v1'][p] == False for p in ports_to_model))
        net_v2_insecure = Or(*(net_var_dict['v2'][p] == True for p in ports_to_model))

        security_drift_proof_2 = And(net_v1_secure, net_v2_insecure)

        service_port = self.service_port
        if service_port in ports_to_model:
            svc_v1_secure = net_var_dict['v1'][service_port] == False
            svc_v2_insecure = net_var_dict['v2'][service_port] == True
            security_drift_proof_3 = And(svc_v1_secure, svc_v2_insecure)
            overall_drift_proof = Or(security_drift_proof,security_drift_proof_2, security_drift_proof_3)
        else:
            security_drift_proof_3 = False
            overall_drift_proof = Or(security_drift_proof, security_drift_proof_2)

        solver.add(overall_drift_proof)

        result = []
        if solver.check() == sat:
            result.append("CRITICAL DRIFT DETECTED: ")

            model = solver.model()
            result.append(f"Proof of Conflict: {model}")

            reasons = []
            if is_true(model.eval(security_drift_proof, model_completion = True)):
                reasons.append("\nAuth Policy Violation: Root login/Password Auth enabled.")
            if is_true(model.eval(security_drift_proof_2, model_completion = True)):
                reasons.append("\nNetwork Policy Violation: Critical Port 22, 23, or 80 are opened.")
            if is_true(model.eval(security_drift_proof_3, model_completion = True)):
                reasons.append(f"\nService Hardening Violation: Debug Port {service_port} (Telnet) was re-enabled.")
            

            if reasons:
                result.append(f"Reason: V1 was secure, but V2 regressed: {' '.join(reasons)}")
            else:
                result.append("Reason: Unknown complex policy violation.")
        else:
            result.append("PASS: Configuration holds the security policy.")
        
        return "\n".join(result)
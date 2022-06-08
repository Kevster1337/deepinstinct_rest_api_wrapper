import deepinstinct30 as di
import datetime, pandas, json, re

def check_policy_setting(expected, actual):
    if str(actual) == expected:
        return str(actual)
    else:
        return '-' + str(actual) + '-'

def prompt_user_for_config():
    di.fqdn = input('Enter FQDN of DI Server, or press enter to accept the default [di-service.customers.deepinstinctweb.com]: ')
    if di.fqdn == '':
        di.fqdn = 'di-service.customers.deepinstinctweb.com'
    di.key = input('Enter API Key for DI Server: ')

def get_windows_policies():
    all_policies = di.get_policies(include_policy_data=True)
    windows_policies = []
    for policy in all_policies:
        if policy['os'] == 'WINDOWS':
            windows_policies.append(policy)
    return windows_policies

def evaluate_policies(policies):
    results = []
    for policy in policies:
        result = {}
        result['policy_id'] = policy['id']
        result['policy_name'] = policy['name']
        result['enable_dcloud_services'] = '-manual_review-'
        result['detection_level'] = check_policy_setting('MEDIUM', policy['detection_level'])
        result['prevention_level'] = check_policy_setting('MEDIUM', policy['prevention_level'])
        result['protection_level_pua'] = check_policy_setting('PREVENT', policy['protection_level_pua'])
        result['scan_network_drives'] = check_policy_setting('True', policy['scan_network_drives'])
        result['embedded_dde_object'] = '-manual_review-'
        result['ransomware_behavior'] = check_policy_setting('PREVENT', policy['ransomware_behavior'])
        result['in_memory_protection'] = check_policy_setting('True', policy['in_memory_protection'])
        result['arbitrary_shellcode_execution'] = check_policy_setting('PREVENT', policy['arbitrary_shellcode_execution'])
        result['remote_code_injection'] = check_policy_setting('PREVENT', policy['remote_code_injection'])
        result['reflective_dll_loading'] = check_policy_setting('PREVENT', policy['reflective_dll_loading'])
        result['reflective_dotnet_injection'] = check_policy_setting('PREVENT', policy['reflective_dotnet_injection'])
        result['amsi_bypass'] = check_policy_setting('PREVENT', policy['amsi_bypass'])
        result['credentials_dump'] = check_policy_setting('PREVENT', policy['credentials_dump'])
        result['known_payload_execution'] = check_policy_setting('PREVENT', policy['known_payload_execution'])
        result['suspicious_script_execution'] = '-manual_review-'
        result['malicious_powershell_command_execution'] = '-manual_review-'
        result['suspicious_activity_detection'] = '-manual_review-'
        result['suspicious_powershell_command_execution'] = '-manual_review-'
        result['office_macro_script_action'] = check_policy_setting('USE_D_BRAIN', policy['office_macro_script_action'])
        result['powershell_script_action'] = check_policy_setting('ALLOW', policy['powershell_script_action'])
        result['html_applications_action'] = check_policy_setting('PREVENT', policy['html_applications_action'])
        result['prevent_all_activescript_usage'] = check_policy_setting('ALLOW', policy['prevent_all_activescript_usage'])
        result['activescript_action'] = check_policy_setting('PREVENT', policy['activescript_action'])
        results.append(result)
    return results

def calculate_export_file_name(policies):
    if di.is_server_multitenancy_enabled():
        server_shortname = re.sub(r'[^a-z0-9]','',policies[0]['msp_name'].lower())
    else:
        server_shortname = di.fqdn.split(".",1)[0]
    file_name = f'policy_evaluation_{datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d_%H.%M")}_UTC_{server_shortname}.xlsx'
    return file_name

def export_results(results, file_name):
    results_df = pandas.DataFrame(results)
    results_df.to_excel(file_name, index=False)
    print('Results written to disk as', file_name, '.')
    print('Non-confirming settings are denoted by wrapping the non-confirming value in hyphens.')
    print('Some settings require manual review until/unless "FR-0000135 - Add missing Windows policy settings to Deep Instinct REST API WindowsPolicyData model" is implemented.')

def add_device_counts(policy_list):
    devices = di.get_devices(include_deactivated=False)
    device_counts = di.count_data_by_field(devices, 'policy_id')
    for policy in policy_list:
        if policy['policy_id'] not in device_counts.keys():
            policy['device_count'] = 0
        else:
            policy['device_count'] = device_counts[policy['policy_id']]
    return policy_list

def main():
    prompt_user_for_config()
    policies = get_windows_policies()
    results = evaluate_policies(policies)
    if input('Do you want to include device counts in the exported data? Warning: This requires pulling all device data from server. On a large environment it will result in a long runtime. Enter YES or NO, or press enter to accept the default [NO]: ').lower() == 'yes':
        results = add_device_counts(results)
    file_name = calculate_export_file_name(policies)
    export_results(results, file_name)

if __name__ == "__main__":
    main()

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

def data_from_more_than_one_msp(policies):
    policy_msp_ids = []
    for policy in policies:
        if policy['msp_id'] not in policy_msp_ids:
            policy_msp_ids.append(policy['msp_id'])
    if len(policy_msp_ids) > 1:
        return True
    else:
        return False

def evaluate_policies(policies, multi_msp):
    results = []
    for policy in policies:
        result = {}
        if multi_msp:
            result['MSP ID'] = policy['msp_id']
            result['MSP Name'] = policy['msp_name']
        result['ID'] = policy['id']
        result['Name'] = policy['name']
        result['D-Cloud Reputation Service'] = '-manual_review-'
        result['Static Analysis PE Detection'] = check_policy_setting('MEDIUM', policy['detection_level'])
        result['Static Analysis PE Prevention'] = check_policy_setting('MEDIUM', policy['prevention_level'])
        result['Known PUA'] = check_policy_setting('PREVENT', policy['protection_level_pua'])
        result['Embedded DDE Objects'] = '-manual_review-'
        result['Network Drive Protection'] = check_policy_setting('True', policy['scan_network_drives'])
        result['Macro Execution'] = check_policy_setting('USE_D_BRAIN', policy['office_macro_script_action'])
        result['Ransomware'] = check_policy_setting('PREVENT', policy['ransomware_behavior'])
        result['In-Memory Protection'] = check_policy_setting('True', policy['in_memory_protection'])
        result['Arbitrary Shellcode'] = check_policy_setting('PREVENT', policy['arbitrary_shellcode_execution'])
        result['Remote Code Injection'] = check_policy_setting('PREVENT', policy['remote_code_injection'])
        result['Reflective DLL Injection'] = check_policy_setting('PREVENT', policy['reflective_dll_loading'])
        result['.Net Reflection'] = check_policy_setting('PREVENT', policy['reflective_dotnet_injection'])
        result['AMSI Bypass'] = check_policy_setting('PREVENT', policy['amsi_bypass'])
        result['Credential Dumping'] = check_policy_setting('PREVENT', policy['credentials_dump'])
        result['Known Payload Executionn'] = check_policy_setting('PREVENT', policy['known_payload_execution'])
        result['Suspicious Script Execution'] = '-manual_review-'
        result['Malicious PowerShell Commands'] = '-manual_review-'
        result['Suspicious Activity Detection'] = '-manual_review-'
        result['Malicious PowerShell Commands'] = '-manual_review-'
        result['PowerShell'] = check_policy_setting('ALLOW', policy['powershell_script_action'])
        result['HTML Applications'] = check_policy_setting('PREVENT', policy['html_applications_action'])
        result['ActiveScript Usage'] = check_policy_setting('ALLOW', policy['prevent_all_activescript_usage'])
        result['ActiveScript Execution'] = check_policy_setting('PREVENT', policy['activescript_action'])
        results.append(result)
    return results

def calculate_export_file_name(policies, mt, multi_msp):
    if mt and not multi_msp:
        server_shortname = re.sub(r'[^a-z0-9]','',policies[0]['msp_name'].lower())
    else:
        server_shortname = di.fqdn.split(".",1)[0]
    file_name = f'policy_evaluation_{datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d_%H.%M")}_UTC_{server_shortname}.xlsx'
    return file_name

def export_results(results, file_name):
    results_df = pandas.DataFrame(results)
    results_df.sort_values(by=['MSP Name','Name'], inplace=True)
    results_df.to_excel(file_name, sheet_name='Policy Audit', index=False)
    print('Results written to disk as', file_name, '.')
    print('Non-confirming settings are denoted by wrapping the non-confirming value in hyphens.')
    print('Some settings require manual review until/unless "FR-0000135 - Add missing Windows policy settings to Deep Instinct REST API WindowsPolicyData model" is implemented.')

def add_device_counts(policy_list):
    devices = di.get_devices(include_deactivated=False)
    device_counts = di.count_data_by_field(devices, 'policy_id')
    for policy in policy_list:
        if policy['ID'] not in device_counts.keys():
            policy['Device Count'] = 0
        else:
            policy['Device Count'] = device_counts[policy['ID']]
    return policy_list

def main():
    prompt_user_for_config()
    policies = get_windows_policies()
    mt = di.is_server_multitenancy_enabled()
    multi_msp = data_from_more_than_one_msp(policies)
    results = evaluate_policies(policies, multi_msp)
    if input('Do you want to include device counts in the exported data? Warning: This requires pulling all device data from server. On a large environment it will result in a long runtime. Enter YES or NO, or press enter to accept the default [YES]: ').lower() != 'no':
        results = add_device_counts(results)
    file_name = calculate_export_file_name(policies, mt, multi_msp)
    export_results(results, file_name)

if __name__ == "__main__":
    main()

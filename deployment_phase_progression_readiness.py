# Disclaimer:
# This code is provided as an example of how to build code against and interact
# with the Deep Instinct REST API. It is provided AS-IS/NO WARRANTY. It has
# limited error checking and logging, and likely contains defects or other
# deficiencies. Test thoroughly first, and use at your own risk. The API
# Wrapper and associated samples are not Deep Instinct commercial products and
# are not officially supported, although he underlying REST API is. This means
# that to report an issue to tech support you must remove the API Wrapper layer
# and recreate the problem with a reproducible test case against the raw/pure
# DI REST API.
#

# import required libraries
import deepinstinct30 as di, json, datetime, pandas, re
from dateutil import parser

# Calculates deployment phase for a Windows policy. Non-conforming and non-Windows policies return 0.
def classify_policy(policy):

    if policy['os'] == 'WINDOWS':

        if policy['prevention_level'] == 'DISABLED':
            return 1

        elif policy['prevention_level'] in ['LOW', 'MEDIUM']:

            if policy['in_memory_protection'] == False:
                return 1.5

            elif policy['in_memory_protection'] == True:
                if policy['remote_code_injection'] == 'DETECT':
                    if policy['arbitrary_shellcode_execution'] == 'DETECT':
                        if policy['reflective_dll_loading'] == 'DETECT':
                            if policy['reflective_dotnet_injection'] == 'DETECT':
                                if policy['amsi_bypass'] == 'DETECT':
                                    if policy['credentials_dump'] == 'DETECT':
                                        if policy['html_applications_action'] == 'DETECT':
                                            if policy['activescript_action'] == 'DETECT':
                                                return 2

                if policy['remote_code_injection'] == 'PREVENT':
                    if policy['arbitrary_shellcode_execution'] == 'PREVENT':
                        if policy['reflective_dll_loading'] == 'PREVENT':
                            if policy['reflective_dotnet_injection'] == 'PREVENT':
                                if policy['amsi_bypass'] == 'PREVENT':
                                    if policy['credentials_dump'] == 'PREVENT':
                                        if policy['html_applications_action'] == 'PREVENT':
                                            if policy['activescript_action'] == 'PREVENT':
                                                return 3

    return 0


# Calculates search parameters for events based on current deployment phase
def get_event_search_parameters(deployment_phase):

    search_parameters = {}
    search_parameters['type'] = []

    #static parameters for all phases
    search_parameters['status'] = ['OPEN']
    search_parameters['threat_severity'] = ['MODERATE', 'HIGH', 'VERY_HIGH']

    #example of how to focus just on a specific timeframe worth of events
    #search_parameters['timestamp'] = {'from': '2022-04-24T00:00:00.000Z', 'to': '2022-05-03T00:00:00.000Z'}

    if deployment_phase in [1, 1.5]:
        search_parameters['type'].append('STATIC_ANALYSIS')
        search_parameters['type'].append('RANSOMWARE_FILE_ENCRYPTION')
        search_parameters['type'].append('SUSPICIOUS_SCRIPT_EXCECUTION')
        search_parameters['type'].append('MALICIOUS_POWERSHELL_COMMAND_EXECUTION')

        if deployment_phase == 1:
            search_parameters['action'] = ['DETECTED']
        else:
            search_parameters['action'] = ['PREVENTED']

    elif deployment_phase in [2]:
        search_parameters['action'] = ['PREVENTED', 'DETECTED']
        search_parameters['type'].append('REMOTE_CODE_INJECTION_EXECUTION')
        search_parameters['type'].append('KNOWN_SHELLCODE_PAYLOADS')
        search_parameters['type'].append('ARBITRARY_SHELLCODE')
        search_parameters['type'].append('REFLECTIVE_DLL')
        search_parameters['type'].append('REFLECTIVE_DOTNET')
        search_parameters['type'].append('AMSI_BYPASS')
        search_parameters['type'].append('DIRECT_SYSTEMCALLS')
        search_parameters['type'].append('CREDENTIAL_DUMP')

    return search_parameters


# Calculates search parameters for suspicious events based on current deployment phase
def get_suspicious_event_search_parameters(deployment_phase):

    suspicious_search_parameters = {}
    suspicious_search_parameters['status'] = ['OPEN']
    suspicious_search_parameters['file_type'] = []
    #search_parameters['type'] = []

    #example of how to focus just on a specific timeframe worth of events
    #suspicious_search_parameters['timestamp'] = {'from': '2022-04-24T00:00:00.000Z', 'to': '2022-05-03T00:00:00.000Z'}

    if deployment_phase in [1, 1.5]:
        #no events from suspicious events list for these phases
        suspicious_search_parameters = None

    elif deployment_phase in [2]:
        suspicious_search_parameters['action'] = ['DETECTED']
        suspicious_search_parameters['file_type'].append('ACTIVE_SCRIPT')
        suspicious_search_parameters['file_type'].append('HTML_APPLICATION')
        #suspicious_search_parameters['type'].append('SCRIPT_CONTROL_COMMAND')
        #suspicious_search_parameters['type'].append('SCRIPT_CONTROL_PATH')

    return suspicious_search_parameters


def run_deployment_phase_progression_readiness(fqdn, key, config):

    print('\nINFO: Beginning analysis')

    di.fqdn = fqdn
    di.key = key
    config = config

    #collect policy data
    print('INFO: Getting policy list and data from server')
    policies = di.get_policies(include_policy_data=True)
    #calculate deployment_phase for each policy and add to policy data
    print('INFO: Evaluating policy data to determine deployment phase(s)')
    print('phase\t id\t name')
    for policy in policies:
        policy['deployment_phase'] = classify_policy(policy)
        if policy['os'] == 'WINDOWS':
            print(policy['deployment_phase'], '\t', policy['id'], '\t', policy['name'])

    #collect event data
    print('INFO: Calculating event search parameters')
    search_parameters = get_event_search_parameters(config['deployment_phase'])

    if not config['ignore_suspicious_events']:
        print('INFO: Calculating suspicious event search parameters')
        suspicious_search_parameters = get_suspicious_event_search_parameters(config['deployment_phase'])

    print('INFO: Querying server for events matching the following criteria:\n', json.dumps(search_parameters, indent=4))
    events = di.get_events(search=search_parameters)
    print('INFO:', len(events), 'events were returned')

    if not config['ignore_suspicious_events']:
        if suspicious_search_parameters != None:
            print('INFO: Querying server for suspicious events matching the following criteria:\n', json.dumps(suspicious_search_parameters, indent=4))
            suspicious_events = di.get_suspicious_events(search=suspicious_search_parameters)
            print('INFO:', len(suspicious_events), 'suspicious events were returned')
            events = events + suspicious_events

    print('INFO:', len(events), 'total events were returned')

    print('INFO: Summarizing event data by device id')
    event_counts = di.count_data_by_field(events, 'device_id')

    #collect device data
    print('INFO: Getting device list from server')
    devices = di.get_devices(include_deactivated=False)
    print('INFO:', len(devices), 'devices were returned')
    print('INFO: Appending deployment phase data to device list')
    for device in devices:
        for policy in policies:
            if policy['id'] == device['policy_id']:
                device['deployment_phase'] = policy['deployment_phase']

    print('INFO: Filtering device data to remove devices not in a phase', config['deployment_phase'], 'policy')
    filtered_devices = []
    for device in devices:
        if device['deployment_phase'] == config['deployment_phase']:
            filtered_devices.append(device)
    devices = filtered_devices
    print('INFO:', len(devices), 'devices remain')

    print('INFO: Adding event count data to device list')
    for device in devices:
        if device['id'] not in event_counts.keys():
            device['event_count'] = 0
        else:
            device['event_count'] = event_counts[device['id']]

    print('INFO: Calculating days since last contact and adding results to device list')
    for device in devices:
        device['last_contact_days_ago'] = (datetime.datetime.now(datetime.timezone.utc) - parser.parse(device['last_contact'])).days

    #add days_since_deployment field to devices
    print('INFO: Adding days_since_deployment to device data by comparing last_registration to current datetime')
    for device in devices:
        device['days_since_deployment'] = (datetime.datetime.now(datetime.timezone.utc) - parser.parse(device['last_registration'])).days

    print('INFO: Evaluating devices to determine which are ready to progress to the next phase')
    for device in devices:
        device['ready_to_move_to_next_phase'] = False
        if device['last_contact_days_ago'] <= int(config['max_days_since_last_contact']):
            if device['event_count'] <= int(config['max_open_event_quantity']):
                device['ready_to_move_to_next_phase'] = True

    print('INFO: Sorting devices into list by readiness')
    devices_ready = []
    devices_not_ready = []
    for device in devices:
        if device['ready_to_move_to_next_phase']:
            devices_ready.append(device)
        else:
            devices_not_ready.append(device)

    print('INFO: Analysis is complete')

    #print summary to console
    print(len(devices_ready), 'of', len(devices), 'devices are ready to progress beyond phase', "{:g}".format(float(config['deployment_phase'])), 'and', len(devices_not_ready), 'devices are not based on this criteria:')
    print(json.dumps(config,indent=4))

    #convert data to be exported to dataframes
    print('INFO: Creating pandas dataframes')
    devices_ready_df = pandas.DataFrame(devices_ready)
    devices_not_ready_df = pandas.DataFrame(devices_not_ready)
    config_df = pandas.DataFrame(config.items())
    search_parameters_df = pandas.DataFrame(search_parameters.items())

    #prep for export
    print('INFO: Preparing export folder and file name')
    folder_name = di.create_export_folder()
    from_deployment_phase = "{:g}".format(float(config['deployment_phase']))
    if di.is_server_multitenancy_enabled():
        server_shortname = re.sub(r'[^a-z0-9]','',policies[0]['msp_name'].lower())
    else:
        server_shortname = di.fqdn.split(".",1)[0]
    file_name = f'deployment_phase_{from_deployment_phase}_progression_readiness_assessment_{datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d_%H.%M")}_UTC_{server_shortname}.xlsx'

    #export dataframes to Excel format
    print('INFO: Exporting dataframes to disk')
    with pandas.ExcelWriter(f'{folder_name}/{file_name}') as writer:
        devices_ready_df.to_excel(writer, sheet_name='ready_for_next_phase', index=False)
        devices_not_ready_df.to_excel(writer, sheet_name='not_ready_for_next_phase', index=False)
        config_df.to_excel(writer, sheet_name='config', index=False)
        search_parameters_df.to_excel(writer, sheet_name='event_search_criteria', index=False)
    print(f'{folder_name}\\{file_name}')
    print('Done.')

def print_readme_on_deployemnt_phases():
    print("""
-----------------
DEPLOYMENT PHASES
-----------------

Phase 1 ("Detection")
4 features, all in detect mode:
-- Static Analysis (Threat Severity on PE files set to ≥ Moderate)
-- Ransomware Behavior
-- Suspicious Script Execution
-- Malicious PowerShell Command Execution

Phase 1.5 ("Prevention Essentials")
All of above moves to Prevent mode.
This phase is OPTIONAL. Most environments choose to move directly from phase 1 to phase 2.

Phase 2 ("Prevention Essentials + Detection Advanced")
All of above moves to Prevent mode.

Add the following in prevent mode (it has no detect mode):
-- In-Memory Protection --> Known Payload Execution

Add the following in detect mode:
-- In-Memory Protection --> Arbitrary Shellcode
-- In-Memory Protection --> Remote Code Injection
-- In-Memory Protection --> Reflective DLL Injection
-- In-Memory Protection --> .Net Reflection
-- In-Memory Protection --> AMSI Bypass
-- In-Memory Protection --> Credential Dumping
-- HTML Applications
-- ActiveScript Execution (JavaScript & VBScript)

Phase 3 ("Advanced Protection")
All of above moves to Prevent mode. Aligns with Prescribed Security Settings:
https://portal.deepinstinct.com/sys/document/preview/Deep-Instinct-Prescribed-Security-Settings-210802120146.pdf
""")


def main():
    #prompt for config
    fqdn = input('Enter FQDN of DI Server, or press enter to accept the default [di-service.customers.deepinstinctweb.com]: ')
    if fqdn == '':
        fqdn = 'di-service.customers.deepinstinctweb.com'

    key = input('Enter API Key for DI Server: ')

    config = {}

    print_readme_on_deployemnt_phases()
    config['deployment_phase'] = 0
    while config['deployment_phase'] not in (1, 1.5, 2):
        config['deployment_phase'] = float(input('Enter the deployment phase of the devices you want to evaluate for readiness to move to a subsequent phase ( 1 | 1.5 | 2 ): '))

    config['max_days_since_last_contact'] = input('Enter the maximum days since Last Contact for a device to be eligible to progress to the next phase, or press enter to accept the default [3]: ')
    if config['max_days_since_last_contact'] == '':
        config['max_days_since_last_contact'] = 3

    config['max_open_event_quantity'] = input('Enter the maximum number of Open Events for a device to be eligible to progress to the next phase, or press enter to accept the default [0]: ')
    if config['max_open_event_quantity'] == '':
        config['max_open_event_quantity'] = 0

    config['ignore_suspicious_events'] = ''
    while config['ignore_suspicious_events'] not in [True, False]:
        user_input = input('Ignore data from the Suspicious Events list? Enter YES or NO, or press enter to accept the default [YES]: ')
        if user_input.lower() in ['yes', '']:
            config['ignore_suspicious_events'] = True
        elif user_input.lower() == 'no':
            config['ignore_suspicious_events'] = False

    return run_deployment_phase_progression_readiness(fqdn=fqdn, key=key, config=config)

if __name__ == "__main__":
    main()

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
#start_time = time.perf_counter()


# -- IMPORT LIBRARIES --
import deepinstinct30 as di
import pandas
import time


# -- CONFIGURATION --

#define server configuration
di.fqdn = 'FOO.customers.deepinstinctweb.com'
di.key = 'BAR'

#define file names to read the exclusions from
process_exclusions_file_name = 'process_exclusions.xlsx'
folder_exclusions_file_name = 'folder_exclusions.xlsx'


# -- RUNTIME --

#read exclusions from files on disk
process_exclusions_dataframe = pandas.read_excel(process_exclusions_file_name)
folder_exclusions_dataframe = pandas.read_excel(folder_exclusions_file_name)

#convert each to a list of dictionaries
process_exclusions = process_exclusions_dataframe.to_dict('records')
folder_exclusions = folder_exclusions_dataframe.to_dict('records')

#get policies
all_policies = di.get_policies()

#filter policy list (Static Analysis exclusions are a Windows-only feature)
windows_policies = []
for policy in all_policies:
    if policy['os'] == 'WINDOWS':
        windows_policies.append(policy)

#iterate through the Windows policies and add the exclusions to each
for policy in windows_policies:

    print('INFO: Adding', len(process_exclusions), 'process exclusions to policy', policy['id'], policy['name'])
    for exclusion in process_exclusions:
        di.add_process_exclusion(exclusion['Process'], exclusion['Comment'], policy['id'])

    print('INFO: Adding', len(folder_exclusions), 'folder exclusions to policy', policy['id'], policy['name'])
    for exclusion in folder_exclusions:
        di.add_folder_exclusion(exclusion['Folder'], exclusion['Comment'], policy['id'])

#runtime_in_seconds = time.perf_counter() - start_time
#print('The above code took a total of', runtime_in_seconds, 'seconds to run')

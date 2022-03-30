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

#import time
#start_time = time.perf_counter()


# -- IMPORT LIBRARIES --
import deepinstinct30 as di
import pandas


# -- CONFIGURATION --

#define server configuration
di.fqdn = 'FOO.customers.deepinstinctweb.com'
di.key = 'BAR'

#define file names to read the exclusions from
process_exclusions_file_name = 'process_exclusions.xlsx'
folder_exclusions_file_name = 'folder_exclusions.xlsx'


# -- RUNTIME --

#read exclusions from files on disk as Pandas dataframes
process_exclusions_dataframe = pandas.read_excel(process_exclusions_file_name)
folder_exclusions_dataframe = pandas.read_excel(folder_exclusions_file_name)

#replace any null values with empty string to avoid subsequent errors
process_exclusions_dataframe.fillna('', inplace=True)
folder_exclusions_dataframe.fillna('', inplace=True)

#convert Pandas dataframes to Python dictionaries
process_exclusions = process_exclusions_dataframe.to_dict('records')
folder_exclusions = folder_exclusions_dataframe.to_dict('records')

#get policy list, then filter it to get a list of just Windows policies
all_policies = di.get_policies()
windows_policies = []
for policy in all_policies:
    if policy['os'] == 'WINDOWS':
        windows_policies.append(policy)

#iterate through each of the Windows policies
for policy in windows_policies:

    print('INFO: Beginning processing of policy', policy['id'], policy['name'])


    #PROCESS EXCLUSIONS

    #create a list to store process exclusions that apply to this policy
    process_exclusions_this_policy = []

    #iterate though the imported process exclusion list
    for exclusion in process_exclusions:
        #check if the exclusion applies to all policies
        if exclusion['Policies'] == 'All':
            process_exclusions_this_policy.append(exclusion)
        #check if the exclusion applies to this specific policy
        elif policy['name'] in exclusion['Policies']:
            process_exclusions_this_policy.append(exclusion)

    #if we found some exclusions applicable to this policy, create them
    if len(process_exclusions_this_policy) > 0:
        print('INFO: Adding', len(process_exclusions_this_policy), 'process exclusions to policy', policy['id'], policy['name'])
        for exclusion in process_exclusions_this_policy:
            di.add_process_exclusion(exclusion['Process'], exclusion['Comment'], policy['id'])


    #FOLDER EXCLUSIONS

    #create a list to store folder exclusions that apply to this policy
    folder_exclusions_this_policy = []

    #iterate though the imported folder exclusion list
    for exclusion in folder_exclusions:
        #check if the exclusion applies to all policies
        if exclusion['Policies'] == 'All':
            folder_exclusions_this_policy.append(exclusion)
        #check if the exclusion applies to this specific policy
        elif policy['name'] in exclusion['Policies']:
            folder_exclusions_this_policy.append(exclusion)

    #if we found some exclusions applicable to this policy, create them
    if len(folder_exclusions_this_policy) > 0:
        print('INFO: Adding', len(folder_exclusions_this_policy), 'folder exclusions to policy', policy['id'], policy['name'])
        for exclusion in folder_exclusions_this_policy:
            di.add_folder_exclusion(exclusion['Folder'], exclusion['Comment'], policy['id'])


    print('INFO: Done with policy', policy['id'], policy['name'])


#runtime_in_seconds = time.perf_counter() - start_time
#print('Runtime was', runtime_in_seconds, 'seconds.')

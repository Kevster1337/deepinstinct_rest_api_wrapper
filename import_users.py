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

import deepinstinct30 as di
import pandas

def run_user_import(fqdn, key, file_name):

    di.fqdn = fqdn
    di.key = key

    #read users to import from file on disk as Pandas dataframe
    user_list_df = pandas.read_excel(file_name)

    #replace any null values with empty string to avoid subsequent errors
    user_list_df.fillna('', inplace=True)

    #convert Pandas dataframe to Python dictionary
    user_list = user_list_df.to_dict('records')


    print('INFO: Successful read', len(user_list), 'records from', file_name)

    #iterate though the imported user list
    for user in user_list:
        di.create_user(username=user['username'], password=user['password'], first_name=user['first_name'], last_name=user['last_name'], email=user['email'], role=user['role'])

def main():

    #prompt for config parameters

    fqdn = input('Enter FQDN of DI Server, or press enter to accept the default [di-service.customers.deepinstinctweb.com]: ')
    if fqdn == '':
        fqdn = 'di-service.customers.deepinstinctweb.com'

    key = input('Enter API Key for DI Server: ')

    print("""
This script accepts input from a single sheet Excel workbook.

The first row of the input file must be column labels, which are cASE SeNSITIve.

The input file must contain the following 6 columns:
    username
    password
    first_name
    last_name
    email
    role

The 'role' column must contain one of these 6 values for each row:
    MASTER_ADMINISTRATOR
    ADMINISTRATOR
    IT_ADMIN
    SOC_ADMIN
    ACCOUNT_ADMINISTRATOR
    READ_ONLY

Column order is irrelevant.

Extra columns are OK and will be ignored.
    """)

    file_name = input('Enter name of file containing users to import, or press enter to accept the default [users.xlsx]: ')
    if file_name == '':
        file_name = 'users.xlsx'

    #run the import
    return run_user_import(fqdn=fqdn, key=key, file_name=file_name)

if __name__ == "__main__":
    main()

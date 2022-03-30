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

#import libraries
import requests, json

#server config
fqdn = 'FOO.customers.deepinstinctweb.com'
key = 'BAR'

#get list of versions from server
request_url = f'https://{fqdn}/api/v1/deployment/agent-versions'
request_headers = {'Authorization': key, 'accept': 'application/json'}
response = requests.get(request_url, headers=request_headers)
available_versions = response.json()

print('These are all the available versions on the server', fqdn)
print(json.dumps(available_versions, indent=4))


#calculate what the latest available Windows version is
highest_windows_version = {'version': '0'}
for version in available_versions:
    if version['os'] == 'WINDOWS':
        if version['version'] > highest_windows_version['version']:
            highest_windows_version = version

print('This is the highest numbered Windows version on the server', fqdn)
print(json.dumps(highest_windows_version, indent=4))


#download the latest available Windows version
request_url = f'https://{fqdn}/api/v1/deployment/download-installer'
request_headers = {'Authorization': key, 'accept': 'application/json', 'Content-Type': 'application/json'}
response = requests.post(request_url, headers=request_headers, json=highest_windows_version)

#write it to disk
file_name = f"deepinstinct_{highest_windows_version['os'].lower()}_{highest_windows_version['version']}.exe"
with open(file_name, 'wb') as f:
    f.write(response.content)

print('The installer was saved to disk as', file_name)

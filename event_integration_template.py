#import required libraries
import deepinstinct30 as di, time

#server configuration
di.fqdn = 'FOO.customers.deepinstinctweb.com'
di.key = 'BAR'

#runtime
last_id = 0
while True:
    events = di.get_events(minimum_event_id=last_id)
    for event in events:
        print(event, '\n') #TODO: Replace with code to forward to SIEM
        if event['id'] > last_id:
            last_id = event['id']
    time.sleep(300) #wait 5 minutes before querying for new events

import deepinstinct30 as di

#server configuration
di.fqdn = 'FOO.customers.deepinstinctweb.com'
di.key = 'BAR'

#runtime

last_id = 0

while True:
    events = di.get_events(minimum_event_id=last_id)
    for event in events:

        #TODO: Insert code here to ingest data in SIEM, generate e-mail, or take
        #      other desired action. For now the placeholder just prints event
        #      to console.
        print(event, '\n')

        if event['id'] > last_id:
            last_id = event['id']
    time.sleep(300) #wait 5 minutes, then query server again for new events

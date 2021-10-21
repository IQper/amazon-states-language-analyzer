# -*- coding: utf-8 -*-

import json
import sys
import requests

def main(input_json):
    token = input_json['token']
    del input_json['token']
    additional = input_json['additional']
    del input_json['additional']

    field_event_import = ''
    link_to_eplat = ''

    headers = {"Authorization": f"Bearer {token}", "Accept":r"application/atom+xml", 'Content-Type':'application/json', 'Accept-Encoding':'gzip, deflate, br', 'Connection':'keep-alive'}
    additional = additional.replace("u003c","<").replace("u003e",">")
    input_json['additional'] = additional
    s = json.dumps(input_json)
    event_field_journal = requests.post(f'http://{link_to_eplat}/{field_event_import}', data = s, headers=headers)
    input_json['send_status'] = str(event_field_journal.status_code)
    input_json['send_message'] = str(event_field_journal.text)
    s = json.dumps(input_json)
    print(s)

if __name__ == '__main__':
    input_str = sys.argv[1]
    input_json = json.loads(input_str)
    main(input_json)
# -*- coding: utf-8 -*-

import sys
import requests
import psycopg2
import re
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import json


def main(input_json):
    connection = psycopg2.connect(user='',
                            password="",
                            host="",
                            port="",
                            database="") 
    connection.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cursor = connection.cursor()

    inc_id = input_json['id']

    cursor.execute('''
                    select 
                        name,
                        source_events_value,
                        additional_info
                    from
                        incidents_all
                    where
                        id = %s
                    ''', (inc_id,))

    inc_fields = cursor.fetchone()
    rule_name = inc_fields[0]
    source_events_value = inc_fields[1]
    event_id = inc_fields[2]
    event_id = re.search(f'(?<=event_id: )(.*?)(?=;)', event_id.lower())

    link_to_eplat = ''
    event_field_journal_export = ''
    eplat_login = ''
    eplat_pass = ''

    token = requests.post(f'http://{link_to_eplat}/api/getToken', data={'password':eplat_pass, 'username':eplat_login, 'grant_type':'password'})
    token = token.json()['access_token']

    headers = {"Authorization": f"Bearer {token}", "Accept":r"application/atom+xml", 'Content-Type':'application/json', 'Accept-Encoding':'gzip, deflate, br', 'Connection':'keep-alive'}
    event_field_journal = requests.get(f'http://{link_to_eplat}/{event_field_journal_export}', headers=headers).json()

    if event_id:
        event_fields_list = list(filter(lambda x: (x['rule_name'] == rule_name) and (x['event_id'] == event_id[0]), event_field_journal))
    else:
        event_fields_list = list(filter(lambda x: x['rule_name'] == rule_name, event_field_journal))

    # source_events_value = 'MSWinEventLog<br>3<br>Security<br>977415<br>Tue Sep 07 11:49:58 2021<br>4625<br>Microsoft-Windows-Security-Auditing<br>N/A<br>N/A<br>Failure Audit<br>mailhub2.I-VOLGA.RU<br>Logon<br>&lt;Event&gt;<br>EventTime:2021-09-07 11:49:58<br>Hostname:mailhub2.I-VOLGA.RU<br>Keywords:-9218868437227405312<br>EventType:AUDIT_FAILURE<br>SeverityValue:4<br>Severity:ERROR<br>EventID:4625<br>SourceName:Microsoft-Windows-Security-Auditing<br>ProviderGuid:{54849625-5478-4994-A5BA-3E3B0328C30D}<br>Version:0<br>Task:12544<br>OpcodeValue:0<br>RecordNumber:249141204<br>ProcessID:776<br>ThreadID:16376<br>Channel:Security<br>&lt;Message&gt;An account failed to log on.<br>Subject:<br>Security ID:  S-1-5-20<br>Account Name:  MAILHUB2$<br>Account Domain:  I-VOLGA<br>Logon ID:  0x3e4<br>Logon Type:   8<br>Account For Which Logon Failed:<br>Security ID:  S-1-0-0<br>Account Name:  oblstom@volganet.ru<br>Account Domain:<br>Failure Information:<br>Failure Reason:  Unknown user name or bad password.<br>Status:   0xc000006d<br>Sub Status:  0xc000006a<br>Process Information:<br>Caller Process ID: 0x1198<br>Caller Process Name: C:\Program Files\Microsoft\Exchange Server\V14\ClientAccess\PopImap\Microsoft.Exchange.Pop3.exe<br>Network Information:<br>Workstation Name: MAILHUB2<br>Source Network Address: -<br>Source Port:  -<br>Detailed Authentication Information:<br>Logon Process:  Advapi<br>Authentication Package: Negotiate<br>Transited Services: -<br>Package Name (NTLM only): -<br>Key Length:  0<br>This event is generated when a logon request fails. It is generated on the computer where access was attempted.<br>The Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.<br>The Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).<br>The Process Information fields indicate which account and process on the system requested the logon.<br>The Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.<br>The authentication information fields provide detailed information about this specific logon request.<br>- Transited services indicate which intermediate services have participated in this logon request.<br>- Package name indicates which sub-protocol was used among the NTLM protocols.<br>- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.<br>Category:Logon<br>Opcode:Info<br>SubjectUserSid:S-1-5-20<br>SubjectUserName:MAILHUB2$<br>SubjectDomainName:I-VOLGA<br>SubjectLogonId:0x3e4<br>TargetUserSid:S-1-0-0<br>TargetUserName:oblstom@volganet.ru<br>Status:0xc000006d<br>FailureReason:%%2313<br>SubStatus:0xc000006a<br>LogonType:8<br>LogonProcessName:Advapi<br>AuthenticationPackageName:Negotiate<br>WorkstationName:MAILHUB2<br>TransmittedServices:-<br>LmPackageName:-<br>KeyLength:0<br>ProcessName:C:\Program Files\Microsoft\Exchange Server\V14\ClientAccess\PopImap\Microsoft.Exchange.Pop3.exe<br>IpAddress:-<br>IpPort:-<br>EventReceivedTime:2021-09-07 11:50:01<br>SourceModuleName:in<br>SourceModuleType:im_msvistalog<br>249141204<br><br>MSWinEventLog<br>3<br>Security<br>977441<br>Tue Sep 07 11:50:24 2021<br>4625<br>Microsoft-Windows-Security-Auditing<br>N/A<br>N/A<br>Failure Audit<br>mailhub2.I-VOLGA.RU<br>Logon<br>&lt;Event&gt;<br>EventTime:2021-09-07 11:50:24<br>Hostname:mailhub2.I-VOLGA.RU<br>Keywords:-9218868437227405312<br>EventType:AUDIT_FAILURE<br>SeverityValue:4<br>Severity:ERROR<br>EventID:4625<br>SourceName:Microsoft-Windows-Security-Auditing<br>ProviderGuid:{54849625-5478-4994-A5BA-3E3B0328C30D}<br>Version:0<br>Task:12544<br>OpcodeValue:0<br>RecordNumber:249141230<br>ProcessID:776<br>ThreadID:16376<br>Channel:Security<br>&lt;Message&gt;An account failed to log on.<br>Subject:<br>Security ID:  S-1-5-20<br>Account Name:  MAILHUB2$<br>Account Domain:  I-VOLGA<br>Logon ID:  0x3e4<br>Logon Type:   8<br>Account For Which Logon Failed:<br>Security ID:  S-1-0-0<br>Account Name:  oblstom@volganet.ru<br>Account Domain:<br>Failure Information:<br>Failure Reason:  Unknown user name or bad password.<br>Status:   0xc000006d<br>Sub Status:  0xc000006a<br>Process Information:<br>Caller Process ID: 0x1198<br>Caller Process Name: C:\Program Files\Microsoft\Exchange Server\V14\ClientAccess\PopImap\Microsoft.Exchange.Pop3.exe<br>Network Information:<br>Workstation Name: MAILHUB2<br>Source Network Address: -<br>Source Port:  -<br>Detailed Authentication Information:<br>Logon Process:  Advapi<br>Authentication Package: Negotiate<br>Transited Services: -<br>Package Name (NTLM only): -<br>Key Length:  0<br>This event is generated when a logon request fails. It is generated on the computer where access was attempted.<br>The Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.<br>The Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).<br>The Process Information fields indicate which account and process on the system requested the logon.<br>The Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.<br>The authentication information fields provide detailed information about this specific logon request.<br>- Transited services indicate which intermediate services have participated in this logon request.<br>- Package name indicates which sub-protocol was used among the NTLM protocols.<br>- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.<br>Category:Logon<br>Opcode:Info<br>SubjectUserSid:S-1-5-20<br>SubjectUserName:MAILHUB2$<br>SubjectDomainName:I-VOLGA<br>SubjectLogonId:0x3e4<br>TargetUserSid:S-1-0-0<br>TargetUserName:oblstom@volganet.ru<br>Status:0xc000006d<br>FailureReason:%%2313<br>SubStatus:0xc000006a<br>LogonType:8<br>LogonProcessName:Advapi<br>AuthenticationPackageName:Negotiate<br>WorkstationName:MAILHUB2<br>TransmittedServices:-<br>LmPackageName:-<br>KeyLength:0<br>ProcessName:C:\Program Files\Microsoft\Exchange Server\V14\ClientAccess\PopImap\Microsoft.Exchange.Pop3.exe<br>IpAddress:-<br>IpPort:-<br>EventReceivedTime:2021-09-07 11:50:27<br>SourceModuleName:in<br>SourceModuleType:im_msvistalog<br>249141230<br><br>MSWinEventLog<br>3<br>Security<br>977513<br>Tue Sep 07 11:51:17 2021<br>4625<br>Microsoft-Windows-Security-Auditing<br>N/A<br>N/A<br>Failure Audit<br>mailhub2.I-VOLGA.RU<br>Logon<br>&lt;Event&gt;<br>EventTime:2021-09-07 11:51:17<br>Hostname:mailhub2.I-VOLGA.RU<br>Keywords:-9218868437227405312<br>EventType:AUDIT_FAILURE<br>SeverityValue:4<br>Severity:ERROR<br>EventID:4625<br>SourceName:Microsoft-Windows-Security-Auditing<br>ProviderGuid:{54849625-5478-4994-A5BA-3E3B0328C30D}<br>Version:0<br>Task:12544<br>OpcodeValue:0<br>RecordNumber:249141302<br>ProcessID:776<br>ThreadID:21548<br>Channel:Security<br>&lt;Message&gt;An account failed to log on.<br>Subject:<br>Security ID:  S-1-5-20<br>Account Name:  MAILHUB2$<br>Account Domain:  I-VOLGA<br>Logon ID:  0x3e4<br>Logon Type:   8<br>Account For Which Logon Failed:<br>Security ID:  S-1-0-0<br>Account Name:  oblstom@volganet.ru<br>Account Domain:<br>Failure Information:<br>Failure Reason:  Unknown user name or bad password.<br>Status:   0xc000006d<br>Sub Status:  0xc000006a<br>Process Information:<br>Caller Process ID: 0x1198<br>Caller Process Name: C:\Program Files\Microsoft\Exchange Server\V14\ClientAccess\PopImap\Microsoft.Exchange.Pop3.exe<br>Network Information:<br>Workstation Name: MAILHUB2<br>Source Network Address: -<br>Source Port:  -<br>Detailed Authentication Information:<br>Logon Process:  Advapi<br>Authentication Package: Negotiate<br>Transited Services: -<br>Package Name (NTLM only): -<br>Key Length:  0<br>This event is generated when a logon request fails. It is generated on the computer where access was attempted.<br>The Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.<br>The Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).<br>The Process Information fields indicate which account and process on the system requested the logon.<br>The Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.<br>The authentication information fields provide detailed information about this specific logon request.<br>- Transited services indicate which intermediate services have participated in this logon request.<br>- Package name indicates which sub-protocol was used among the NTLM protocols.<br>- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.<br>Category:Logon<br>Opcode:Info<br>SubjectUserSid:S-1-5-20<br>SubjectUserName:MAILHUB2$<br>SubjectDomainName:I-VOLGA<br>SubjectLogonId:0x3e4<br>TargetUserSid:S-1-0-0<br>TargetUserName:oblstom@volganet.ru<br>Status:0xc000006d<br>FailureReason:%%2313<br>SubStatus:0xc000006a<br>LogonType:8<br>LogonProcessName:Advapi<br>AuthenticationPackageName:Negotiate<br>WorkstationName:MAILHUB2<br>TransmittedServices:-<br>LmPackageName:-<br>KeyLength:0<br>ProcessName:C:\Program Files\Microsoft\Exchange Server\V14\ClientAccess\PopImap\Microsoft.Exchange.Pop3.exe<br>IpAddress:-<br>IpPort:-<br>EventReceivedTime:2021-09-07 11:51:18<br>SourceModuleName:in<br>SourceModuleType:im_msvistalog<br>249141302'

    result = []
    sorted_event_fields_list = []
    result_str = []

    sorted_event_fields_list = sorted(event_fields_list, key=lambda x: int(x['number']))

    for i in sorted_event_fields_list:
        if i['field_value']:
            field_value = i['field_value']
            m = re.findall(f'(?<={field_value.lower()}:)(.*?)(?=<br>)', source_events_value.lower())
            result.append((i['field_description'], ', '.join(m)))
        else:
            result.append((i['field_description'], i['field_value']))

    for i in result:
        result_str.append(f'{i[0]} {i[1]}')

    if event_id:
        input_json['event_id'] = event_id[0]
    input_json['additional'] = ';<br>'.join(result_str).replace('"', "'")
    input_json['token'] = token

    print(json.dumps(input_json))

if __name__ == '__main__':
    input_str = sys.argv[1]
    input_json = json.loads(input_str)
    main(input_json)
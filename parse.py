import json
import re
import requests

false_ips = []

res = requests.get('https://app.statuscake.com/Workfloor/Locations.php?format=json')

if res.ok:
    locations_map = json.loads(res.content)
    locations = [loc['ip'] for loc_id, loc in locations_map.items()]

    blocked_ips = []
    blocked_ips_file = open('ufw_status_numbered_output_example.txt')

    for row in blocked_ips_file.readlines():
        pattern = re.compile('\[\s*([0-9]+)\].*(DENY|ALLOW) IN\s+([a-f0-9\.\:]+).*')
        match = pattern.search(row)

        if match:
            blocked_ip = {
                'id': match.group(1),
                'rule': match.group(2),
                'ip': match.group(3),
            }

            blocked_ips.append(blocked_ip)

            if blocked_ip['ip'] in locations:
                false_ips.append(blocked_ip)

    false_ips_reversed_by_id = sorted(false_ips, key=lambda rule: rule['id'], reverse=True)

    for rule in false_ips_reversed_by_id:
        print('# Delte command for rule {rule} IN from ip {ip} with id {id}'.format(**rule))
        print("yes | sudo ufw delete {id}".format(**rule))

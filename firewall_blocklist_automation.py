import requests, csv, subprocess, time, re

badIPS = []
#get the list of blocked IPV4 from Feedotracker for source-Abuse 
response = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt").text
response2 = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json").json()

#Use regex find ip addresses that matched IPV4
ips = re.findall(r'\d+.\d+.\d+.\d+', response)

#Loop through the json result and append the result
for i1 in response2:
  badIPS.append(i1['ip_address'])

#Loop through the result and skip any entry with dates
for i in ips:
    if i.startswith("2023-06-26 00"):
        continue
    badIPS.append(i)

#Delete the old block rules using the powershell command
rule="netsh advfirewall firewall delete rule name='Blacklisted'"
subprocess.run(["Powershell", "-Command", rule])

#Filter for duplicate before addding to firewall
for ip in set(badIPS):

  print("Added rule to block", ip)

#Write back the new blocked IPS in outbound 
  rule="netsh advfirewall firewall add rule name='Blacklisted' Dir=out Action=Block RemoteIP="+ip
  subprocess.run(["Powershell", "-Command", rule])
#Write back the new blocked IPS in inbound 
  rule="netsh advfirewall firewall add rule name='Blacklisted' Dir=in Action=Block RemoteIP="+ip
  subprocess.run(["Powershell", "-Command", rule])

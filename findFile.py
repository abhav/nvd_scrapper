import requests
import re

r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
# permanent File
fp = open("years.txt","w+")
for filename in re.findall("nvdcve-1.1-[0-9]*\.json\.zip",r.text):
    fp.write(str(filename) + "\n")
fp.close()

# temporary File
ft = open("recent.txt","w+")
for filename in re.findall("nvdcve-1.1-[a-z]*\.json\.zip",r.text):
    ft.write(str(filename) + "\n")
ft.close()
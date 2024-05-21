import csv
import requests
import json
import time

apikey = '<VT_API_KEY>'
hashes = open("input_hash.txt") # the hashes to check

with open("virustotal_hash_analysis.csv", mode="w", newline="") as analysis:
    writer = csv.writer(analysis)
    writer.writerow(["VTlink", "Filetype", "Undetected", "Suspicious", "Malicious"])
    analysis.close()


for hashn in hashes:
  
  with open("movie_analysis.csv", mode="a", newline="") as analysis:
    writer = csv.writer(analysis)

    print('Checking hash ' + hashn)
    url = "https://www.virustotal.com/api/v3/files/"
    VTlink= "https://www.virustotal.com/gui/file/"
    headers = {
      "accept": "application/json",
      "x-apikey": "<VT_API_KEY>"
      }
    
    hashn = hashn.strip()
    response= requests.get(url+hashn, headers=headers, timeout= 120)

    if response.status_code == 404:
      result = response.json()         
      analysis.write(VTlink+hashn.strip() + ","+ "Not Found in Virus Total Database"+"\n")

    elif response.status_code == 200:
      result = response.json()
# write only the files recognized as malicious
      writer.writerow([
        VTlink + hashn.strip(),
        result['data']['attributes']['magic'],
        result['data']['attributes']['last_analysis_stats']['undetected'],
        result['data']['attributes']['last_analysis_stats']['suspicious'],
        result['data']['attributes']['last_analysis_stats']['malicious']
])
      analysis.close()
    time.sleep(1 * 20)

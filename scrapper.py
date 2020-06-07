import requests
import zipfile
import io
import json
import pandas as pd
import sys
# print(sys.argv)

fp = open(str(sys.argv[1]) + ".txt", "r")
fl = fp.readlines()
fp.close()

nvd_data = []
product_data = []
cpe_data = []
cvss_data = []

for filename in fl:
    print('Extracting from: ' + filename)
    r_zip_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename[:-1], stream=True)
    zip_file_bytes = io.BytesIO()

    for chunk in r_zip_file:
        zip_file_bytes.write(chunk)

    zip_file = zipfile.ZipFile(zip_file_bytes)
    # Only 1 file in each zip folder so refer by 0 index
    json_raw = zip_file.read(zip_file.namelist()[0]).decode('utf-8')
    json_data = json.loads(json_raw)

    for CVE_Item in json_data['CVE_Items']:
        cve_id = CVE_Item['cve']['CVE_data_meta']['ID']  # get CVE
        # if description exists
        try:
            cve_description = CVE_Item['cve']['description']['description_data'][0]['value']
        except:
            cve_description = 'NULL'

        # CPE Version range
        try:
            cve_cpe_node = CVE_Item['configurations']['nodes']
            for node in cve_cpe_node:
                if node['operator'] == 'OR':
                    for cpe_match in node['cpe_match']:
                        try:
                            versionStartExcluding = cpe_match['versionStartExcluding']
                        except:
                            versionStartExcluding = 'NULL'
                        try:
                            versionStartIncluding = cpe_match['versionStartIncluding']
                        except:
                            versionStartIncluding = 'NULL'
                        try:
                            versionEndExcluding = cpe_match['versionEndExcluding']
                        except:
                            versionEndExcluding = 'NULL'
                        try:
                            versionEndIncluding = cpe_match['versionEndIncluding']
                        except:
                            versionEndIncluding = 'NULL'
                        cpe_uri = cpe_match['cpe23Uri']
                        product_list = cpe_uri.split(':')
                        product_data.append([cve_id, product_list[3], product_list[4], product_list[5]])
                        cpe_data.append(
                            [cve_id, cpe_uri, versionStartExcluding, versionStartIncluding, versionEndExcluding,
                             versionEndIncluding])
                else:
                    node_child = node['children']
                    for child in node_child:
                        for cpe_match in child['cpe_match']:
                            try:
                                versionStartExcluding = cpe_match['versionStartExcluding']
                            except:
                                versionStartExcluding = 'NULL'
                            try:
                                versionStartIncluding = cpe_match['versionStartIncluding']
                            except:
                                versionStartIncluding = 'NULL'
                            try:
                                versionEndExcluding = cpe_match['versionEndExcluding']
                            except:
                                versionEndExcluding = 'NULL'
                            try:
                                versionEndIncluding = cpe_match['versionEndIncluding']
                            except:
                                versionEndIncluding = 'NULL'
                            cpe_uri = cpe_match['cpe23Uri']
                            product_list = cpe_uri.split(':')
                            product_data.append([cve_id, product_list[3], product_list[4], product_list[5]])
                            cpe_data.append(
                                [cve_id, cpe_uri, versionStartExcluding, versionStartIncluding, versionEndExcluding,
                                 versionEndIncluding])
        except:
            print('Error in: ' + cve_id)

        # if impact V3 exists
        try:
            cve_cvss3_score = CVE_Item['impact']['baseMetricV3']['cvssV3']['baseScore']
        except:
            cve_cvss3_score = 'NULL'

        # if impact V2 exists
        try:
            cve_cvss2_score = CVE_Item['impact']['baseMetricV2']['cvssV2']['baseScore']
        except:
            cve_cvss2_score = 'NULL'

        # if publish date
        try:
            cve_publishedDate = CVE_Item['publishedDate']
        except:
            cve_publishedDate = 'NULL'

        # if modifed date
        try:
            cve_lastModifiedDate = CVE_Item['lastModifiedDate']
        except:
            cve_lastModifiedDate = 'NULL'

        nvd_data.append([cve_id, cve_description, cve_publishedDate, cve_lastModifiedDate])
        if cve_cvss2_score != 'NULL':
            cvss_data.append([cve_id, cve_cvss2_score, 'cvss2'])
        if cve_cvss3_score != 'NULL':
            cvss_data.append([cve_id, cve_cvss3_score, 'cvss3'])
    print('Extracting complete from: ' + filename)

# Remove Duplicate Rows and store in csv
my_df = pd.DataFrame(nvd_data)
my_df.drop_duplicates(keep=False,inplace=True)
my_df.to_csv('nvd_data.csv', index=False, header=False)

my_df = pd.DataFrame(cvss_data)
my_df.drop_duplicates(keep=False,inplace=True)
my_df.to_csv('cvss_data.csv', index=False, header=False)

my_df = pd.DataFrame(product_data)
my_df.drop_duplicates(keep=False,inplace=True)
my_df.to_csv('product_data.csv', index=False, header=False)

my_df = pd.DataFrame(cpe_data)
my_df.drop_duplicates(keep=False,inplace=True)
my_df.to_csv('cpe_data.csv', index=False, header=False)
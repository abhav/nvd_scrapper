import psycopg2
import csv

conn = psycopg2.connect("host=localhost dbname=Synopsys user=postgres password=1234")

cur = conn.cursor()

cur.execute("TRUNCATE nvd, cvss, cpe_version, product CASCADE;")
print('All Tables Truncated')
with open('nvd_data.csv', 'r') as f:
    reader = csv.reader(f)
    # next(reader) # Skip the header row.
    for row in reader:
        cur.execute("INSERT INTO nvd VALUES (%s, %s, %s, %s);", row)
print('NVD transferred successfully ')

with open('cvss_data.csv', 'r') as f:
    reader = csv.reader(f)
    # next(reader) # Skip the header row.
    for row in reader:
        cur.execute("INSERT INTO cvss VALUES (%s, %s, %s);", row)
print('CVSS transferred successfully ')

with open('cpe_data.csv', 'r') as f:
    reader = csv.reader(f)
    # next(reader) # Skip the header row.
    for row in reader:
        cur.execute("INSERT INTO cpe_version VALUES (%s, %s, %s, %s, %s, %s);", row)
print('CPE transferred successfully ')

with open('product_data.csv', 'r') as f:
    reader = csv.reader(f)
    # next(reader) # Skip the header row.
    for row in reader:
        cur.execute("INSERT INTO product VALUES (%s, %s, %s, %s);", row)
print('Product transferred successfully ')

conn.commit()
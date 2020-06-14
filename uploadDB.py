import psycopg2
import csv
from configDB import sql_conn


class AddRecord:
    conn = psycopg2.connect(sql_conn)
    cur = conn.cursor()
    def truncatePrevious(self):
        self.cur.execute("TRUNCATE nvd, cvss, cpe_version, product CASCADE;")
        print('All Tables Truncated')

    def insertRecord(self):
        with open('nvd_data.csv', 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                self.cur.execute("INSERT INTO nvd VALUES (%s, %s, %s, %s);", row)
        print('NVD transferred successfully ')

        with open('cvss_data.csv', 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                self.cur.execute("INSERT INTO cvss VALUES (%s, %s, %s);", row)
        print('CVSS transferred successfully ')

        with open('cpe_data.csv', 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                self.cur.execute("INSERT INTO cpe_version VALUES (%s, %s, %s, %s, %s, %s);", row)
        print('CPE transferred successfully ')

        with open('product_data.csv', 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                self.cur.execute("INSERT INTO product VALUES (%s, %s, %s, %s);", row)
        print('Product transferred successfully ')
        self.conn.commit()
        self.conn.close()
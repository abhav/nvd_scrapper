import psycopg2
from configDB import sql_conn


class LiveQueries:
    def excuteAndPrint(self, command):
        conn = psycopg2.connect(sql_conn)
        cur = conn.cursor()
        cur.execute(command)
        records = cur.fetchall()
        for record in records:
            print(record)
        conn.commit()
        conn.close()
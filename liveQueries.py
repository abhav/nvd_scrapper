import psycopg2
from singleExecutor import sql_conn

conn = psycopg2.connect(sql_conn)
cur = conn.cursor()


class LiveQueries:
    def excute(self, command):
        cur.execute(command)

    def printRecords(self):
        records = cur.fetchall()

        for record in records:
            print(record)


lv = LiveQueries()

# What are the top 10 most vulnerable products? (Based on the number of CVEs associated with them on a version basis.)
command1 = " SELECT type, subtype, version, COUNT(id) AS most_vulnerable \
    FROM     product \
    GROUP BY type, subtype, version \
    ORDER BY most_vulnerable DESC \
    LIMIT    10;"
print('Query 1 execution')
lv.excute(command1)
print('Query 1 Result')
lv.printRecords()

# Show the breakdown of the number of CVEs per whole-number score (round up)
command2 = " CREATE TEMP TABLE temp1 AS \
    SELECT id, type, CEIL(score) as Rounded_Score \
        FROM  cvss; \
    SELECT type, Rounded_Score, COUNT(id) AS NoOfCVE \
        FROM temp1 \
        GROUP BY Rounded_Score, type \
        ORDER BY type, Rounded_Score DESC; \
        "
print('Query 2 execution')
lv.excute(command2)
print('Query 2 Result')
lv.printRecords()

conn.commit()

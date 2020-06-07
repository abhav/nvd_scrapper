import psycopg2

conn = psycopg2.connect("host=localhost dbname=Synopsys user=postgres password=1234")

cur = conn.cursor()
# What are the top 10 most vulnerable products? (Based on the number of CVEs associated with them on a version basis.)
cur.execute("""SELECT type, subtype, version, COUNT(id) AS most_vulnerable 
    FROM     product
    GROUP BY type, subtype, version
    ORDER BY most_vulnerable DESC
    LIMIT    10;""")

records = cur.fetchall()
print('Query 1 Result')
for record in records:
    print(record)

# Show the breakdown of the number of CVEs per whole-number score (round up)
cur.execute("""CREATE TEMP TABLE temp1 AS
    SELECT id, type, CEIL(score) as Rounded_Score
        FROM  cvss;
    SELECT type, Rounded_Score, COUNT(id) AS NoOfCVE
        FROM temp1
        GROUP BY Rounded_Score, type
        ORDER BY type, Rounded_Score DESC;
        """)

print('Query 2 Result')
records = cur.fetchall()
for record in records:
    print(record)

conn.commit()

import psycopg2
from configDB import sql_conn

conn = psycopg2.connect(sql_conn)

cur = conn.cursor()

print('Creating NVD Table')
cur.execute("""CREATE TABLE IF NOT EXISTS nvd(
    id text ,
    description text,
    publishedDate date,
    lastModifiedDate date,
    CONSTRAINT nvd_pkey PRIMARY KEY (id)
    )
    """)
print('Created NVD Table')

print('Creating cvss Table')
cur.execute("""CREATE TABLE IF NOT EXISTS cvss
    (
    id text,
    score numeric,
    type text,
    CONSTRAINT cve_id FOREIGN KEY (id)
        REFERENCES nvd (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
    )""")
print('Created cvss Table')

print('Creating cpr_version Table')
cur.execute("""CREATE TABLE IF NOT EXISTS cpe_version
    (
    id text,
    cpe_uri text,
    versionStartExcluding text,
    versionStartIncluding text,
    versionEndExcluding text,
    versionEndIncluding text,
    CONSTRAINT cve_id FOREIGN KEY (id)
        REFERENCES nvd (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
    )""")
print('Created cpe_version Table')

print('Creating product Table')
cur.execute("""CREATE TABLE IF NOT EXISTS product
    (
    id text,
    type text,
    subType text,
    version text,
    CONSTRAINT cve_id FOREIGN KEY (id)
        REFERENCES nvd (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
    )""")
print('Created product Table')

conn.commit()
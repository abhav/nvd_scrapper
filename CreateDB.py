import psycopg2

conn = psycopg2.connect("host=localhost dbname=Synopsys user=postgres password=1234")

cur = conn.cursor()

cur.execute("""CREATE TABLE IF NOT EXISTS nvd(
    id text ,
    description text,
    publishedDate date,
    lastModifiedDate date,
    CONSTRAINT nvd_pkey PRIMARY KEY (id)
    )
    """)
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

conn.commit()
# nvd_scrapper


Pre-Requisite:

Libraries Required: requests, re, zipfile, json, pandas, psycopg2, csv
Software/ Environment Required: Postgres, Python 3.x

------------------------------------------------------------------------------------
--Set DB string in singleExecutor

From  -"host=localhost dbname=Synopsys user=postgres password=1234"
To - Appropriate in your system

------------------------------------------------------------------------------------
Steps to run:

python singleExecutor.py

Explanation:

	Assumptions
		-- Data for CPE/ version range and product. 
		-- In live query for most vulnerable product - it is assumed from core product to version basis for example - Google:Android:8.0 and not Android:8.0. It can be simply be changed by changing GROUP BY column in query.
		-- In live query to show the breakdown of the number of CVEs per whole-number score (round up) - cvss2 and cvss3 is considered different, and therefore 20 records are obtained.

Steps - 
1. Extract file name from webpage
2. Extract Data from zip file and store in temp CSV's
3. Create DB table
4. Upload data in DB tables
5. Remove temp files
6. Run live Queries


Data Models Created:

Table Nvd
 - id text ,
 - description text,
 - publishedDate date,
 - lastModifiedDate date,
  - CONSTRAINT nvd_pkey PRIMARY KEY (id)

Table cvss
 - id text ,
 - score numeric,
 - type text,
 - CONSTRAINT cve_id FOREIGN KEY (id)


Table cpe
 - id text ,
 - cpe_uri text,
 - versionStartExcluding text,
 - versionStartIncluding text,
 - versionEndExcluding text,
 - versionEndIncluding text,
 - CONSTRAINT cve_id FOREIGN KEY (id)


Table product
 - id text ,
 - type text,
 - subType text,
 - version text,
 - CONSTRAINT cve_id FOREIGN KEY (id)

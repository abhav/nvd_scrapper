# nvd_scrapper


Pre-Requisite:

Libraries Required: requests, re, zipfile, json, pandas, psycopg2, csv

Software/ Environment Required: Postgres, Python 3.x

------------------------------------------------------------------------------------
--Set DB string in configDB.py

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
1. Extract file name from webpage (findFile.py)
2. Extract Data from zip file and store in temp CSV's (scrapper.py)
3. Create DB table (createDB.py)
4. Upload data in DB tables (uploadDB.py)
5. Remove temp files 
6. Run live Queries (liveQueries.py)


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

Note:

1. Indices can be created o speed up execution. For example if we add indices to find the most vulnerable products

--CREATE INDEX product_type ON product(type);

--DROP INDEX product_type;

CREATE INDEX product_type ON product(type, subtype, version );

EXPLAIN ANALYZE SELECT type, subtype, version, COUNT(id) AS most_vulnerable     
	FROM     product     
	GROUP BY type, subtype, version     
	ORDER BY most_vulnerable DESC     
	LIMIT    10;	
	
With No indices:
- Successfully run. Total query runtime: 3 secs 236 msec. 

With type as indice: (Not significant improvement)
- Successfully run. Total query runtime: 3 secs 19 msec.

With multiple indices: (significant improvement))
- Successfully run. Total query runtime: 1 secs 333 msec.

Similarly, we can make indices for query 2: by column name - Rounded_Score abd type

Decision to add indices is based on user requirements(balancing space vs time). 

2. These 23 records were not following the configuration cpe pattern of node -> child for operator 'AND'
 - Error in cpe Extraction from cve_id: CVE-2017-14023
 - Error in cpe Extraction from cve_id: CVE-2020-10257
 - Error in cpe Extraction from cve_id: CVE-2019-12216
 - Error in cpe Extraction from cve_id: CVE-2019-12217
 - Error in cpe Extraction from cve_id: CVE-2019-12218
 - Error in cpe Extraction from cve_id: CVE-2019-12219
 - Error in cpe Extraction from cve_id: CVE-2019-12220
 - Error in cpe Extraction from cve_id: CVE-2019-12221
 - Error in cpe Extraction from cve_id: CVE-2019-12395
 - Error in cpe Extraction from cve_id: CVE-2019-18251
 - Error in cpe Extraction from cve_id: CVE-2019-18426
 - Error in cpe Extraction from cve_id: CVE-2019-18937
 - Error in cpe Extraction from cve_id: CVE-2019-18939
 - Error in cpe Extraction from cve_id: CVE-2018-10511
 - Error in cpe Extraction from cve_id: CVE-2018-1258
 - Error in cpe Extraction from cve_id: CVE-2015-1188
 - Error in cpe Extraction from cve_id: CVE-2015-8875
 - Error in cpe Extraction from cve_id: CVE-2014-7874
 - Error in cpe Extraction from cve_id: CVE-2014-8756
 - Error in cpe Extraction from cve_id: CVE-2013-4412
 - Error in cpe Extraction from cve_id: CVE-2012-4838
 - Error in cpe Extraction from cve_id: CVE-2009-2273
 - Error in cpe Extraction from cve_id: CVE-2008-6714

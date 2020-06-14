import requests
from findFile import FindFile
from scrapper import Scrap
from createDB import createTable
import os
from uploadDB import AddRecord
from liveQueries import LiveQueries

print('Lets Begin')
print('Find Relevant Files on Webpage')
r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
ff = FindFile(r)
ff.filesFound()
print('Files Found : ')
print(ff.files)
print('----------------------------------------------------')
print('Now start extracting data from files on webpage')
scrapping = Scrap()
scrapping.startScrap(ff.files)
scrapping.saveDatatoCSV()
print('CSV Created')
print('----------------------------------------------------')

print('Create DB to Upload Data')
createTable()
print('----------------------------------------------------')

print('Upload Data to tables')
addRecords = AddRecord()
addRecords.truncatePrevious()      # optional
addRecords.insertRecord()
print('----------------------------------------------------')

print('Remove temp data Created')
os.system('rm -r *.csv')
print('----------------------------------------------------')

print('Run Live Queries')
lv = LiveQueries()
print('Query 1: What are the top 10 most vulnerable products? '
      '(Based on the number of CVEs associated with them on a version basis.')
command1 = " SELECT type, subtype, version, COUNT(id) AS most_vulnerable \
    FROM     product \
    GROUP BY type, subtype, version \
    ORDER BY most_vulnerable DESC \
    LIMIT    10;"
print('Query 1 execution')
lv.excuteAndPrint(command1)

print('Query 2 : Show the breakdown of the number of CVEs per whole-number score (round up)')
command2 = " CREATE TEMP TABLE temp1 AS \
    SELECT id, type, CEIL(score) as Rounded_Score \
        FROM  cvss; \
    SELECT type, Rounded_Score, COUNT(id) AS NoOfCVE \
        FROM temp1 \
        GROUP BY Rounded_Score, type \
        ORDER BY type, Rounded_Score DESC; \
        "
print('Query 2 execution')
lv.excuteAndPrint(command2)
print('----------------------------------------------------')
import os
sql_conn = 'host=localhost dbname=Synopsys user=postgres password=1234'

print('Lets Begin')
print('Find Relevant Files on Webpage')
os.system('python findFile.py')

print('Now start extracting data from files on webpage')
os.system('python scrapper.py years')

print('Create DB to Upload Data')
os.system('python createDB.py')

print('Upload Data to tables')
os.system('python uploadDB.py 1')

print('Remove temp data Created')
os.system('rm -r *.csv')
os.system('rm -r *.txt')

print('Run Live Queries')
os.system('python liveQueries.py')

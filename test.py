import csv
import psycopg2

conn = psycopg2.connect("postgresql://neondb_owner:npg_uc7D3lUgbRHF@ep-spring-union-a4705hj0-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require")
cur = conn.cursor()

with open('backend/data.csv', newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        cur.execute("""
    INSERT INTO MeterData (
       LastCommunicationDatetime, MeterId, MeterType, CommunicationMedium, CTWC
    ) VALUES (%s, %s, %s, %s, %s)
""", (

            row['LastCommunicationDatetime'],
            row['MeterId'],
            row['MeterType'],
            row['CommunicationMedium'],
            row['CTWC'],
        ))


conn.commit()
cur.close()
conn.close()

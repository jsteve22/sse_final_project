import sqlite3

# sqlite name
DB_NAME = 'db.sqlite'

def make_dist_table():
  con = sqlite3.connect(f'{DB_NAME}')
  cur = con.cursor()
  try:
    cur.execute('CREATE TABLE dist(groupid STRING, artifactid STRING);')
  except:
    print('command did not execute; could not create dist table')
  return

def make_vuls_table():
  con = sqlite3.connect(f'{DB_NAME}')
  cur = con.cursor()
  try:
    cur.execute('''CREATE TABLE vuls( 
      productid INTEGER, 
      startversion STRING, 
      endversion STRING, 
      year STRING, 
      severity STRING, 
      cwe STRING, 
      cveid STRING,
      description STRING,
      FOREIGN KEY(productid) REFERENCES dist(rowid)
      );''')
  except: 
    print('command did not execute; could not create vuls table')
  return

def drop_table(table_name):
  con = sqlite3.connect(f'{DB_NAME}')
  cur = con.cursor()
  try:
    cur.execute(f'DROP TABLE {table_name};')
  except:
    print(f'command did not execute; could not create {table_name} table')
  

def drop_dist_table():
  drop_table('dist')
  return

def drop_vuls_table():
  drop_table('vuls')
  return

def reset_db():
  drop_dist_table()
  make_dist_table()
  drop_vuls_table()
  make_vuls_table()
  print(f'RESET: {DB_NAME}')
  return

def add_dist(groupId, artifactId, con=None):
  con = con or sqlite3.connect(f'{DB_NAME}')
  cur = con.cursor()
  cur.execute(f'INSERT INTO dist VALUES("{groupId}","{artifactId}");')
  con.commit()
  return

def add_vuls(productId, startVersion, endVersion, year, severity, cwe, cveId, description, con=None):
  con = con or sqlite3.connect(f'{DB_NAME}')
  cur = con.cursor()
  cur.execute(f'INSERT INTO vuls VALUES({productId},"{startVersion}","{endVersion}","{year}","{severity}","{cwe}","{cveId}","{description}");')
  con.commit()
  return

def fuzzy_search_dist(vendor, product):
  con = sqlite3.connect(f'{DB_NAME}')
  cur = con.cursor()
  res = cur.execute(f'SELECT *, rowid FROM dist WHERE groupid LIKE "%{vendor}%" AND artifactid LIKE "%{product}%"')
  return res.fetchall()

def search_vuls(productId):
  con = sqlite3.connect(f'{DB_NAME}')
  cur = con.cursor()
  res = cur.execute(f'SELECT * FROM vuls WHERE productid = {productId}')
  return res.fetchall()

def add_vul_to_db(entry, year):
  # get all data necessary for vuls table entry
  cve_id = entry['cve']['CVE_data_meta']['ID']
  cwe_id = entry['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']
  severity = entry['impact']['baseMetricV3']['cvssV3']['baseSeverity']
  description = entry['cve']['description']['description_data'][0]['value']

  # if cve_id == 'CVE-2023-2798':
  #   print(entry)

  startVersion = ''
  endVersion = ''
  vendor = ''
  product = ''
  for cpe_match in entry['configurations']['nodes'][0]['cpe_match']:
    if 'cpe23Uri' not in cpe_match.keys():
      continue
    cpe23Uri = cpe_match['cpe23Uri'].split(':')
    vendor = cpe23Uri[3]
    product = cpe23Uri[4]

    startVersion = ''
    endVersion = ''

    if 'versionStartIncluding' in cpe_match.keys():
      startVersion = cpe_match['versionStartIncluding']

    if 'versionEndExcluding' in cpe_match.keys():
      endVersion = cpe_match['versionEndExcluding']

    # get productId from dist table if possible
    res = fuzzy_search_dist(vendor, product)
    if len(res) == 0:
      add_dist(vendor, product)
      res = fuzzy_search_dist(vendor, product)

    productId = res[0][2]

    if endVersion == '':
      endVersion = startVersion
    
    if endVersion == '' and startVersion == '':
      continue

    add_vuls(productId, f'{startVersion}', f'{endVersion}', year, severity, cwe_id, cve_id, description)
  return

def main():
  res = fuzzy_search_dist('google', 'gmail')
  print(res)
  pass

if __name__ == '__main__':
  main()


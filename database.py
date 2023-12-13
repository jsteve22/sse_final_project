import sqlite3

# sqlite name
DB_NAME = 'db.sqlite'

def make_packages_table():
    con = sqlite3.connect(f'{DB_NAME}')
    cur = con.cursor()
    try:
        cur.execute('CREATE TABLE packages(name STRING, version STRING);')
    except:
        print('command did not execute; could not create packages table')
    return

def make_functions_table():
    con = sqlite3.connect(f'{DB_NAME}')
    cur = con.cursor()
    try:
        cur.execute('''CREATE TABLE functions( 
                                              packageid INTEGER, 
                                              callpath STRING,
                                              purpose STRING,
                                              qresistant BOOLEAN,
                                              FOREIGN KEY(packageid) REFERENCES packages(rowid)
        );''')
    except: 
        print('command did not execute; could not create functions table')
    return

def drop_table(table_name):
    con = sqlite3.connect(f'{DB_NAME}')
    cur = con.cursor()
    try:
        cur.execute(f'DROP TABLE {table_name};')
    except:
        print(f'command did not execute; could not drop {table_name} table')

def drop_packages_table():
    drop_table('packages')
    return

def drop_functions_table():
    drop_table('functions')
    return

def reset_db():
    drop_packages_table() 
    make_packages_table() 
    drop_functions_table()
    make_functions_table()
    print(f'RESET: {DB_NAME}')
    return

def add_package(name, version, con=None):
    con = con or sqlite3.connect(f'{DB_NAME}')
    cur = con.cursor()
    cur.execute(f'INSERT INTO packages VALUES("{name}","{version}");')
    con.commit()
    con.close()
    return

def fuzzy_search_packageid(packagename):
    con = sqlite3.connect(f'{DB_NAME}')
    cur = con.cursor()
    res = cur.execute(f'SELECT *, rowid FROM packages WHERE name LIKE "%{packagename}%"')
    return res.fetchall()[0][2]

def add_function(packagename, callpath, purpose, qresistant, con=None):
    con = con or sqlite3.connect(f'{DB_NAME}')
    cur = con.cursor()
    cur.execute(f'INSERT INTO functions VALUES({fuzzy_search_packageid(packagename)},"{callpath}","{purpose}",{qresistant});')
    con.commit()
    con.close()
    return

def get_packages():
    con = sqlite3.connect(f'{DB_NAME}')
    cur = con.cursor()
    res = cur.execute(f'SELECT * FROM packages')
    return res.fetchall()

def get_functions():
    con = sqlite3.connect(f'{DB_NAME}')
    cur = con.cursor()
    res = cur.execute(f'SELECT * FROM functions')
    return res.fetchall()

def get_package_functions(packagename):
    con = sqlite3.connect(f'{DB_NAME}')
    cur = con.cursor()
    res = cur.execute(f'SELECT * FROM functions WHERE packageid = {fuzzy_search_packageid(packagename)}')
    return res.fetchall()

def main():
    reset_db()
    add_package('cryptography', '41.0.7')
    add_function('cryptography', 'cryptography.hazmat.primitives.asymmetric.rsa', 'PKE', False)
    return

if __name__ == '__main__':
    main()

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

def better_function(functionpath, con=None):
    con = con or sqlite3.connect(f'{DB_NAME}')
    cur = con.cursor()
    res = cur.execute(f'SELECT * FROM functions WHERE callpath LIKE "{functionpath}" LIMIT 1')
    ret = res.fetchall()
    if not ret:
        return '', ''

    packageid, _, purpose, qresistant = ret[0]

    res = cur.execute(f'SELECT * FROM functions WHERE packageid = {packageid} AND purpose LIKE "{purpose}" and qresistant = {True}')
    ret = res.fetchall()

    if not ret:
        return '', ''

    return ret[0][1], ret[0][2]

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
    res = cur.execute(f'SELECT *, rowid FROM packages WHERE name LIKE "{packagename}"')
    x = res.fetchall()
    # names = [r for r in x]
    # print(names)
    return x[0][2]

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

    # add cryptography package
    add_package('cryptography', '41.0.7')
    add_function('cryptography', 'cryptography.hazmat.primitives.asymmetric.rsa', 'PKE', False)
    add_function('cryptography', 'cryptography.hazmat.primitives.asymmetric.dh', 'PKE', False)
    add_function('cryptography', 'cryptography.hazmat.primitives.asymmetric.ed25519', 'PKE', False)
    add_function('cryptography', 'cryptography.hazmat.primitives.asymmetric.ed448', 'PKE', False)
    add_function('cryptography', 'cryptography.hazmat.primitives.asymmetric.kyber', 'PKE', True)

    # add M2Crypto package
    add_package('M2Crypto', '0.40.1')
    add_function('M2Crypto', 'M2Crypto.RSA', 'PKE', False)
    add_function('M2Crypto', 'M2Crypto.DSA', 'PKE', False)
    add_function('M2Crypto', 'M2Crypto.DH', 'PKE', False)

    # add PyCryptodome package
    add_package('Crypto', '3.19.0')
    add_function('Crypto', 'Crypto.PublicKey.RSA', 'PKE', False)
    add_function('Crypto', 'Crypto.Cipher.DES', 'SKE', False) # add this to test if program can detect DES function call

    add_package('Cryptodome', '3.19.0')
    add_function('Cryptodome', 'Cryptodome.Cipher.DES', 'SKE', False) # add this to test if program can detect DES function call

    # add PyNaCl package
    add_package('PyNaCl', '1.5.0')
    add_function('PyNaCl', 'nacl.public', 'PKE', False)

    return

if __name__ == '__main__':
    main()

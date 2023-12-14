# main.py
# Author: Jeremy Stevens
import database as db

def main():
    all_packages = db.get_packages()
    print(f'all_packages = {all_packages}')

    all_functions = db.get_functions()
    print(f'all_functions = {all_functions}')

    return

if __name__ == '__main__':
    main()

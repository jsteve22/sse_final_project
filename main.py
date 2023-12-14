# main.py
# Author: Jeremy Stevens
import database as db
import scanfiles as scan
import crawl_directory as crawl
import sys

def find_packages_in_files(files, packages):
    combined = []

    for file in files:
        for package in packages:
            if scan.is_package_included(file, package[0]):
                combined.append( (file, package) )

    return combined

def search_vul_functions(vul_files):
    
    for vf in vul_files:
        file, package = vf

        packagename = package[0]

        functions = db.get_package_functions(packagename)

        func_paths = [f[1] for f in functions]

        bad_code = scan.lookup_functions_in_file(file, func_paths)

        if bad_code:
            print(f'{len(bad_code)} vulnerabilities found in {file}:')
            for bc in bad_code:
                print(f'\t{bc}')
            print()

    return 

def main():
    # all_packages = db.get_packages()
    # print(f'all_packages = {all_packages}')

    # all_functions = db.get_functions()
    # print(f'all_functions = {all_functions}')

    if len(sys.argv) > 1:
        d = sys.argv[1]
    else:
        d = 'test'

    files = crawl.get_relevant_files(d)
    all_packages = db.get_packages()

    vul_files = find_packages_in_files(files, all_packages)

    search_vul_functions(vul_files)

    return

if __name__ == '__main__':
    main()

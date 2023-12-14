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
                # print( (file, package) )
    
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
                function_path = ''
                called_function = bc[1].split('.')[0]
                for fp in bc[2]:
                    # print(f'fp = {fp}')
                    if called_function in fp:
                        function_path = fp
                        break
                print(f'\t{bc[0]}')
                print(f'\t{bc[3].rstrip()}')
                qresistant, purpose = db.better_function(function_path)
                if qresistant:
                    print(f'\tReplace function call with `{qresistant}` as it is quantum resistant and is also {purpose}')

            print()

    return 

def process_requirements_file(files):
    req_files = []

    # get all requirements.txt files from directory
    for file in files:
        if 'requirements.txt' in file:
            req_files.append(file)

    packages = db.get_packages()

    for file in req_files:
        vul_packages = scan.check_requirements(file, packages)

        # if nothing is found, return with no issues
        if not vul_packages:
            continue

        print(f'{len(vul_packages)} errors found in {file}')
        for vul in vul_packages:
            pname, pversion, pcurr = vul
            print(f'{pname} is set to {pcurr} when it should be {pversion} or higher')
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
        print(f'python main.py: missing directory to scan')
        print(f"Try 'python main.py test' to run static analysis tool on 'test' directory")
        return

    files = crawl.get_relevant_files(d)
    all_packages = db.get_packages()

    # print(f'files founded: {files}')
    process_requirements_file(files)

    vul_files = find_packages_in_files(files, all_packages)

    search_vul_functions(vul_files)

    return

if __name__ == '__main__':
    main()

# main.py
# Author: Jeremy Stevens

import sys
import inspect

# 1. load in a libraries to analyze (i.e. cryptography library)
# 2. then load in methods for that library to analyze in code (i.e. cryptography.hazmat.primitives.asymmetric.rsa )
# 3. load files from a project repository
# 4. go through each file and search if there is a call to any of those dangerous functions
# 5. consolidate those function calls into a report and return that report to the user
# 6. provide an explanation for why that is dangerous and then ways to update it

def main():

    dfs = load_dangerous_functions()

    libraries = list(set([df.library for df in dfs]))

    possible_files = ['./cryptography_rsa_example.py']

    possible_files = files_with_affected_libraries(possible_files, libraries)


    return 

class DangerousFunction():

    def __init__(self, library, function_path, danger_level,resolution):
        self.library = library
        self.function_path = function_path 
        self.danger_level = danger_level 
        self.resolution = resolution 

def load_dangerous_functions():
    # for now, hard code dangerous functions in the cryptography library

    ret = []

    df = DangerousFunction('cryptography', 'cryptography.hazmat.primitives.asymmetric.rsa', 'Warning: quantum-vulnerable', 'Update RSA to quantum resistant schemes such as CRYSTALS-Kyber')

    ret.append(df)
    
    return ret

def load_file(file_path):
    with open(file_path, 'r') as r:
        return r.readlines()

def files_with_affected_libraries(files, libraries):
    ret = []
    for file in files:
        lines = load_file(file)
        lines = [line.rstrip() for line in lines]

        included = False
        for line in lines:
            for lib in libraries:
                if lib in line:
                    included = True
                    break
        if not included:
            continue
        ret.append( file )

    return ret

if __name__ == '__main__':
    main()

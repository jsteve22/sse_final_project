# scanfiles.py

import re
import ast
import inspect

def load_file(file_path):
    try:
        with open(file_path, 'r') as r:
            return r.readlines()
    except:
        return []

def is_package_included(filename, packagename):
    # go through each line in the file and check to see if the package 
    # is imported in that file

    filelines = load_file(filename)

    for line in filelines:
        is_import = re.match(f'\S*import {packagename}.*', line)
        if bool(is_import):
            return True

        is_import = re.match(f'\S*from {packagename}(.[a-zA-Z0-9]+)* import.*', line)
        if bool(is_import):
            return True

    # no package found in the file
    return False

def print_is_package_included(filename, packagename):
    res = is_package_included(filename, packagename)
    print(f'{packagename} in {filename} == {res}')
    return

def test_is_package_included():
    print_is_package_included('test_main.py', 'cryptography')
    print_is_package_included('main.py', 'cryptography')
    print_is_package_included('scanfiles.py', 'cryptography')
    print_is_package_included('cryptography_rsa_example.py', 'cryptography')
    return

def collect_vulnerabilities(tree, functionpaths, lines, filename=''):
    # module_levels = [functionpath]
    module_levels = functionpaths.copy()

    vulnerabilities = []

    def traverse(node, context):
        # method call, loops, ...
        # print(ast.unparse(node))
        if isinstance(node, ast.Call):
            # print(f'Call: {ast.unparse(node)} \tcontext: {context}')
            # for child in ast.iter_child_nodes(node):
                # print(f'Child: {ast.unparse(child)}')
            # print()
            function_call = ''
            for field in ast.iter_fields(node):
                # print(f'field: {field}')
                if field[0] == 'func':
                    # print(ast.unparse(field[1]))
                    function_call = ast.unparse(field[1])
            # print(function_call)
            for mod_level in module_levels:
                if bool(re.match(f'{mod_level}(\.[a-zA-Z0-9]+)*', function_call)):
                    # print(f'Dangerous function call {function_call} used on line {node.lineno}')
                    vulnerabilities.append( (f'Line {node.lineno}: Dangerous function call {function_call}', function_call, functionpaths, lines[node.lineno-1]) )
                    # vulnerabilities.append( f'Line {node.lineno}: Dangerous function call {function_call}' )
            # print()
            pass
        elif isinstance(node, ast.Import):
            # print(f'Import: {ast.unparse(node)} \tcontext: {context}')
            curr_path = ''
            for field in ast.iter_fields(node):
                # print(f'field: {field}')
                if field[0] == 'names':
                    curr_path = field[1][0].name
            # *x, _ = curr_path.split('.')
            # curr_path = '.'.join(x)
            for mod_level in module_levels:
                if bool(re.match(f'{curr_path}(\.[a-zA-Z0-9]+)*', mod_level)):
                    _, extra_path = mod_level.split(curr_path)
                    if extra_path[1:]:
                        module_levels.append(extra_path[1:])
                    break
            # print()
            pass
        elif isinstance(node, ast.ImportFrom):
            # print(f'ImportFrom: {ast.unparse(node)} \tcontext: {context}')
            curr_path = ''
            curr_call = ''
            for field in ast.iter_fields(node):
                # print(f'field: {field}')
                if field[0] == 'names':
                    curr_call = field[1][0].name
                if field[0] == 'module':
                    curr_path = field[1]
            # print(f'call path: {curr_path}.{curr_call}')
            imported = f'{curr_path}.{curr_call}'
            # print(f'imported: {imported}')

            # if the imported is also in module levels, add new definition to module levels
            for mod_level in module_levels:
                if bool(re.match(f'{imported}(\.[a-zA-Z0-9]+)*', mod_level)):
                    _, extra_path = mod_level.split(curr_call)
                    module_levels.append(curr_call + extra_path)
                    break
                # if bool(re.match(f'{mod_level}(\.[a-zA-Z0-9]+)*', imported)):
                    # _, extra_path = imported.split(mod_level)
                    # module_levels.append(extra_path)
                    # break

            # print()
            pass
        for child in ast.iter_child_nodes(node):
            # print(f'{ast.unparse(child).rstrip()}')
            traverse(child, context)
        return

    traverse(tree, [])
    # print(f'{filename} - module_levels: {module_levels}')
    return vulnerabilities

def lookup_functions_in_file(filename, functionpaths):
    lines = load_file(filename)
    source_code = ''.join(lines)

    source_ast = ast.parse(source_code)

    bad_code = collect_vulnerabilities(source_ast, functionpaths, lines, filename)
    return bad_code

def is_updated_version(up_to_date_version, prod_version):
    up_to_date_list = [int(v) if v else 0 for v in up_to_date_version.split('.')]
    prod_list = [int(v) if v else 0 for v in prod_version.split('.')]

    # append 0's to the end of each list
    size = max(len(up_to_date_list), len(prod_list))
    up_to_date_list = up_to_date_list + ([0]*(size-len(up_to_date_list)))
    prod_list = prod_list + ([0]*(size-len(prod_list)))

    # prod should be greater or equal to up_to_date
    for utd, p in zip(up_to_date_list, prod_list):
        if utd > p:
            return False
    return True

def check_requirements(filename, packages):
    lines = load_file(filename)

    vul_libraries = []

    for line in lines:
        line = line.rstrip()
        for package in packages:
            pname, pversion = package
            if '==' in line and pname == line.split('==')[0]:
                curr_version = line.split('==')[1]
                if not is_updated_version(pversion, curr_version):
                    vul_libraries.append( (pname, pversion, curr_version) )
            elif pname == line:
                vul_libraries.append( (pname, pversion, '') )

    return vul_libraries

def main():
    # test_is_package_included()
    lookup_functions_in_file('cryptography_rsa_example.py', ['cryptography.hazmat.primitives.asymmetric.rsa'])
    return

if __name__ == '__main__':
    main()

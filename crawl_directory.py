import os
import re

def crawl_directory(directory, output=None):
    output = output or []
    for file in os.listdir(directory):
        new_path = f'{directory}/{file}'
        output.append(f'{directory}/{file}')
        if os.path.isdir(new_path):
            crawl_directory(new_path, output)
    return output

def get_relevant_files(directory):
    all_files = crawl_directory(directory)

    relevant_files = []
    for file in all_files:
      if '.py' in file or 'requirement.txt' in file:
        relevant_files.append( file )
    return relevant_files
  
def main():
    output = get_relevant_files('./test')
    print(output)
    return

if __name__ == '__main__':
    main()
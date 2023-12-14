# sse_final_project

This repository will hold all of the files necessary to implement the final project for SSE FA23. 

### Using Tool
To use the tool, make sure that you have all of the necessary libraries installed with 
```
pip -r requirements.txt
```

After ensuring the necessary packages are installed, you can then run the program with
```
python3 main.py [directory]
```
where the directory holds all of the code you want to analyze. 

In this repository, test and unsafe_code are two different directories that store examples to use the tool on. 
The test repository holds custom files and also the [moto](https://github.com/getmoto/moto) codebase.
The unsafe_code directory holds all of the files that were tested on using Bandit to generate an accuracy score. 
The database is stored in db.sqlite and is updated using the database.py file. 
Everything was ran on Python 3.10.12, but should work properly with Python3+.

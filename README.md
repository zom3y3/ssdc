# ssdc
Cluster Analysis for Malware Sample Files
Inspired by https://github.com/bwall/ssdc

# Usage
```
usage: ssdc.py [-h] [-s SCORE] [-t TYPE] [-g] [-d] [-e EXCLUDE] [-j JSONFILE]
              FILEPATH

positional arguments:
 FILEPATH              Specific the File Directory

optional arguments:
 -h, --help            show this help message and exit
 -s SCORE, --score SCORE
                       Specific the similarity score, list of choices: {0,
                       30, 60, 90} (default: 60)
 -t TYPE, --type TYPE  Specific the cluster type, list of choices:
                       {file_ssdeep, strings_ssdeep, imp_exp_ssdeep}
                       (default: file_ssdeep)
 -g, --gather          Put the similar files together to a new file directory
                       (default: False)
 -d, --delete          Delete the similar files (default: False)
 -e EXCLUDE, --exclude EXCLUDE
                       Exclude similar files in this file Directory (default:
                       None)
 -j JSONFILE, --jsonfile JSONFILE
                       Save cluster json report to this file (default: None)

Mail bug reports and suggestions to <zom3y3@gmail.com>
```

#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Github/Twitter: @zom3y3
# Email: zom3y3@gmail.com
# Inspired by https://github.com/bwall/ssdc

import os
import json
import base64
import hashlib
import shutil
import ssdeep
import time
import argparse
import lief
from struct import unpack
from glob import iglob

def file_md5(file):
    if os.path.exists(file):
        f = open(file, 'rb')
        m = hashlib.md5(f.read())
        md5 = m.hexdigest()
        f.close()
        return md5

def imp_exp_functions(filepath):
    try:
        imp_functions = lief.parse(filepath).imported_functions
        exp_functions = lief.parse(filepath).exported_functions
    except Exception as e:
        imp_functions = ''
        exp_functions = ''

    imp_exp_function_str = ''
    for imp in imp_functions:
        imp_exp_function_str += imp

    for exp in exp_functions:
        imp_exp_function_str += exp

    return imp_exp_function_str

class SSDC():
    def __init__(self, filepath, score, type='file_ssdeep', exclude_files=''):
        self.similar_score = score
        self.hashes = {}
        self.sha256s = {}
        self.integerdb = {}
        self.matches = {}
        self.scores = {}
        self.groups = []
        self.file_lists = []
        self.ssdeep_stats = {}
        self.tmpdir = os.getcwd() + os.sep + str(time.time()) + os.sep
        self.filepath = filepath
        self.exclude_files = exclude_files
        self.count = 0
        self.cluster_type = type
        self.cluster_report = {}

    def gen_ssdeep_hash(self, filepath, exclude=False):
        files = os.listdir(filepath)
        for file in files:
            if not os.path.isfile(filepath + file):
                print "[+] WARNING: %s is not a file and will not analysis it. " %(filepath + file)
                continue
            tmp_ssdeep_hash = ''
            if self.cluster_type == 'strings_ssdeep':
                data = os.popen('strings %s' % (filepath + file)).read()

                tmp_ssdeep_hash = ssdeep.hash(data)
            elif self.cluster_type == 'file_ssdeep':
                tmp_ssdeep_hash = ssdeep.hash_from_file(filepath + file)

            elif self.cluster_type == 'imp_exp_ssdeep':
                imp_exp_str = imp_exp_functions(filepath + file)
                if imp_exp_str:
                    tmp_ssdeep_hash = ssdeep.hash(imp_exp_str)

            if tmp_ssdeep_hash:
                dst_file = self.tmpdir + str(self.count)
                f = open(dst_file, 'w')
                f.write(tmp_ssdeep_hash)
                f.close()
                self.count += 1
                if tmp_ssdeep_hash not in self.ssdeep_stats.keys():
                    self.ssdeep_stats[tmp_ssdeep_hash] = []
                tmp_file_ssdeep = {}
                tmp_file_ssdeep['file_path'] = filepath + file
                tmp_file_ssdeep['file_md5'] = file_md5(filepath + file)
                tmp_file_ssdeep['cluster_type'] = self.cluster_type
                tmp_file_ssdeep['exclude'] = 1 if exclude else 0
                self.ssdeep_stats[tmp_ssdeep_hash].append(tmp_file_ssdeep)

    def cluster_start(self):
        if not os.path.exists(self.tmpdir):
            os.makedirs(self.tmpdir)

        self.gen_ssdeep_hash(self.filepath, exclude=False)

        if self.exclude_files:
            self.gen_ssdeep_hash(self.exclude_files, exclude=True)

        self.file_lists = self.enumerate_paths(self.tmpdir.split())

    def cluster_finish(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)
        self.gen_cluster_report()

    def handle(self):
        self.cluster_start()
        # parepare ssdeep_lists
        ssdeep_sets = set()
        for path in self.file_lists:
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if len(line) == 0:
                        continue
                    ssdeep_sets.add(line)
        ssdeep_lists = list(ssdeep_sets)

        # print '> ssdeep cluster'
        for path in ssdeep_lists:
            if ',' in path:
                shash, path = path.split(',', 1)
                path = path.strip('"')
            else:
                shash = path
            self.hashes[path] = shash
            self.sha256s[path] = hashlib.sha256(path).hexdigest()

            block_size, chunk, double_chunk = self.process_ssdeep_hash(self.hashes[path])

            similar_to = self.insert2db(block_size, chunk, path) | self.insert2db(block_size * 2, double_chunk, path)

            h = self.hashes[path]
            self.matches[path] = set()
            for other in similar_to:
                score = ssdeep.compare(h, self.hashes[other])
                if score > self.similar_score:
                    self.matches[path].add(other)
                    self.matches[other].add(path)
                    if path not in self.scores:
                        self.scores[path] = {}
                    if other not in self.scores[path]:
                        self.scores[path][other] = score

                    if other not in self.scores:
                        self.scores[other] = {}
                    if path not in self.scores[other]:
                        self.scores[other][path] = score

        # ssdeep groups
        for path in self.matches.keys():
            in_a_group = False
            for g in xrange(len(self.groups)):
                if path in self.groups[g]:
                    in_a_group = True
                    continue
                should_add = True
                for h in self.groups[g]:
                    if h not in self.matches[path]:
                        should_add = False
                if should_add:
                    self.groups[g].append(path)
                    in_a_group = True
            if not in_a_group:
                self.groups.append([path])

        for g in xrange(len(self.groups)):
            self.groups[g].sort()

        self.cluster_finish()

    def gen_cluster_report(self):
        tmp_cluster_result = []
        for group in xrange(len(self.groups)):
            tmp_ssdeep_group = {}
            group_name = "cluster_" + str(group)
            tmp_ssdeep_group[group_name] = {}
            for ssdeep_hash in self.groups[group]:
                tmp_ssdeep_group[group_name][ssdeep_hash] = []
                for file_ssdeep in self.ssdeep_stats[ssdeep_hash]:
                    tmp_file = {}
                    tmp_file['file_path'] = file_ssdeep['file_path']
                    tmp_file['file_md5'] = file_ssdeep['file_md5']
                    tmp_ssdeep_group[group_name][ssdeep_hash].append(tmp_file)


            tmp_cluster_result.append(tmp_ssdeep_group)
        self.cluster_report['type'] = self.cluster_type
        self.cluster_report['score'] = self.similar_score
        self.cluster_report['result'] = tmp_cluster_result

    def get_all_7_char_chunks(self, h):
        return set((unpack('<Q', base64.b64decode(h[i:i + 7] + '=') + '\x00\x00\x00')[0] for i in xrange(len(h) - 6)))

    def process_ssdeep_hash(self, h):
        block_size, h = h.split(':', 1)
        block_size = int(block_size)
        # Reduce any sequence of the same char greater than 3 to 3
        for c in set(list(h)):
            while c * 4 in h:
                h = h.replace(c * 4, c * 3)
        block_data, double_block_data = h.split(':')
        return block_size, self.get_all_7_char_chunks(block_data), self.get_all_7_char_chunks(double_block_data)

    def insert2db(self, block_size, chunk, path):
        if block_size not in self.integerdb:
            self.integerdb[block_size] = {}

        similar_to = set()
        for i in chunk:
            if i not in self.integerdb[block_size]:
                self.integerdb[block_size][i] = set()
            else:
                similar_to |= self.integerdb[block_size][i]
            self.integerdb[block_size][i].add(path)
        return similar_to

    def enumerate_paths(self, path_list):
        ret_paths = []
        while len(path_list) != 0:
            file_path = os.path.abspath(path_list[0])
            del path_list[0]
            if os.path.isfile(file_path):
                ret_paths.append(file_path)
            elif os.path.isdir(file_path):
                for p in iglob(os.path.join(file_path, '*')):
                    p = os.path.join(file_path, p)
                    if os.path.isfile(p):
                        path_list.append(p)
        return ret_paths

    def delete_similars(self):
        #delete similar files
        for group in xrange(len(self.groups)):
            if (len(self.groups[group])) > 1:
                tmp_filepaths = []
                for ssdeep_hash in self.groups[group]:
                    for file_ssdeep in self.ssdeep_stats[ssdeep_hash]:
                        tmp_filepaths.append(file_ssdeep['file_path'])
                tmp_filepaths = list(set(tmp_filepaths))
                for i in range(1, len(tmp_filepaths)):
                    if os.path.exists(tmp_filepaths[i]):
                        os.remove(tmp_filepaths[i])

    def delete_exclude(self):
        #delete exclude similar files
        tmp_filepaths = []
        for group in xrange(len(self.groups)):
            group_exclude = False
            for ssdeep_hash in self.groups[group]:
                for file_ssdeep in self.ssdeep_stats[ssdeep_hash]:
                    if file_ssdeep['exclude']:
                        group_exclude = True
                        break
                if group_exclude:
                    break

            if group_exclude:
                for ssdeep_hash in self.groups[group]:
                    for file_ssdeep in self.ssdeep_stats[ssdeep_hash]:
                        if not file_ssdeep['exclude']:
                            tmp_filepaths.append(file_ssdeep['file_path'])

        for k,v in self.ssdeep_stats.items():
            if len(v) > 1:
                flag1 = False
                flag2 = False
                for file_ssdeep in v:
                    if not file_ssdeep['exclude']:
                        flag1 = True
                    if file_ssdeep['exclude']:
                        flag2 = True
                if flag1 and flag2:
                    for file_ssdeep in v:
                        if not file_ssdeep['exclude']:
                            tmp_filepaths.append(file_ssdeep['file_path'])

        # print tmp_filepaths
        tmp_filepaths = list(set(tmp_filepaths))
        for i in range(len(tmp_filepaths)):
            if os.path.exists(tmp_filepaths[i]):
                os.remove(tmp_filepaths[i])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, epilog='Mail bug reports and suggestions to <zom3y3@gmail.com>')
    cluster_types = ['file_ssdeep', 'strings_ssdeep', 'imp_exp_ssdeep']
    similar_scores = ['0', '30', '60', '90']
    parser.add_argument(dest='filepath', metavar='FILEPATH', help='Specific the File Directory')
    parser.add_argument('-s', '--score', dest='score', metavar='SCORE', choices=similar_scores, help='Specific the similarity score, list of choices: {%(choices)s}', default='60')
    parser.add_argument('-t', '--type', dest='type', metavar='TYPE', choices=cluster_types, help='Specific the cluster type, list of choices: {%(choices)s}', default='file_ssdeep')
    parser.add_argument('-g', '--gather', dest='gather', action='store_true', help='Put the similar files together to a new file directory')
    parser.add_argument('-d', '--delete', dest='delete', action='store_true', help='Delete the similar files')
    parser.add_argument('-e', '--exclude', dest='exclude', help='Exclude similar files in this file Directory')
    parser.add_argument('-j', '--jsonfile', dest='jsonfile', help='Save cluster json report to this file')

    args = parser.parse_args()

    analysis_path = args.filepath

    if args.score:
        score = int(args.score)
    else:
        score = 90

    if args.type:
        cluetr_type = args.type
    else:
        cluetr_type = 'file_ssdeep'

    if args.exclude:
        exclude = args.exclude
    else:
        exclude = ''

    if args.delete and args.gather:
        print "[+] WARNING: args.delete dosen't work when args.gather is on. "
    starttime = time.time()
    print '> Clustering ...'
    s = SSDC(analysis_path, score, type=cluetr_type, exclude_files=exclude)
    s.handle()
    cluster_report = s.cluster_report
    print '> {0} ssdeep hashes cluster into {1} groups'.format(len(s.hashes), len(s.groups))

    if args.gather:
        for cluster in cluster_report['result']:
            for cluster_name, cluster_data in cluster.items():
                for ssdeep_hash, ssdeep_files in cluster_data.items():
                    for ssdeep_file in ssdeep_files:
                        filedir = '/'.join(ssdeep_file['file_path'].split('/')[0:-1])
                        filename = ssdeep_file['file_path'].split('/')[-1]
                        dst_path = os.path.join(filedir, '%s/%s' % (cluster_report['type'], cluster_name))
                        dst_file = os.path.join(dst_path, filename)
                        if not os.path.exists(dst_path):
                            os.makedirs(dst_path)
                        shutil.copy(ssdeep_file['file_path'], dst_file)

        print '> Put the similar files together to %s' %(dst_path)

    if args.delete and not args.gather:
        print '> Delete the similar files'
        if args.exclude:
            s.delete_exclude()
        s.delete_similars()

    if args.jsonfile:
        jsonfile = args.jsonfile
        json_report = json.dumps(s.cluster_report, sort_keys=True, indent=4, separators=(',', ': '))
        f = open(jsonfile, 'w')
        f.write(json_report)
        f.close()
        print '> Save cluster json report to %s' %(jsonfile)
    endtime = time.time()
    print '> Time Usage: ' + str(endtime - starttime)

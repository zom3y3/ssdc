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
import types
import lief
from struct import unpack
from glob import iglob
import subprocess
import re
import requests
from elftools.common.py3compat import (ifilter, byte2int, bytes2str, itervalues, str2bytes)
from elftools.elf.elffile import ELFFile

requests.packages.urllib3.disable_warnings()


def get_section_ssdeep(file):
    section_hash_result = {}
    try:
        elffile = ELFFile(file)
        file.seek(0)
        elfdata = file.read()
        for nsec, section in enumerate(elffile.iter_sections()):
            section_data = elfdata[int(section['sh_offset']):int(section['sh_offset']) + int(section['sh_size'])]
            section_hash_result[bytes2str(section.name)] = ssdeep.hash(section_data)
    except Exception as e:
        print str(e)
        pass
    return section_hash_result

def get_section_data(file):
    section_hash_result = {}
    try:
        elffile = ELFFile(file)
        file.seek(0)
        elfdata = file.read()
        for nsec, section in enumerate(elffile.iter_sections()):
            section_data = elfdata[int(section['sh_offset']):int(section['sh_offset']) + int(section['sh_size'])]
            section_hash_result[bytes2str(section.name)] = section_data
    except Exception as e:
        print str(e)
        pass
    return section_hash_result

def file_md5(file):
    if os.path.exists(file):
        f = open(file, 'rb')
        m = hashlib.md5(f.read())
        md5 = m.hexdigest()
        f.close()
        return md5

def str_md5(str):
    try:
        if type(str) is types.StringType:
            m = hashlib.md5()
            m.update(str)
            return m.hexdigest()
        else:
            print type(str)
            return ''
    except Exception as e:
        return ''

#only works for ELF
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

def eset_scan(filepath):
    scan_json = {}
    scan_json['threats'] = []
    eset_cmd = "/opt/eset/esets/sbin/esets_scan --no-sfx --adware --unsafe --unwanted --no-mail --no-mailbox --clean-mode=none %s" %(filepath)
    process = subprocess.Popen(eset_cmd.split(), stdout=subprocess.PIPE)
    eset_result = process.stdout.read()
    process.stdout.close()
    version_regex = r'Module scanner, version ([^\n]*), build ([^\n]*)'
    version_match = re.search(version_regex, eset_result)
    if version_match:
        scan_json['database_version'] = version_match.group(1)
        scan_json['build_version'] = version_match.group(2)

    threat_regex = r'name="([^\n]*)", threat="([^\n]*)", action="([^\n]*)", info="([^\n]*)"'
    threat_match = re.finditer(threat_regex, eset_result)
    for threatmatch in threat_match:
        tmp_threat_result = {}
        tmp_threat_result['filename'] = threatmatch.group(1)
        tmp_threat_result['name'] = ' '.join(threatmatch.group(2).split(' ')[:-1]).replace(' potentially unwanted', '').replace(' potentially unsafe', '').replace('probably ', '')
        tmp_threat_result['type'] = threatmatch.group(2).split(' ')[-1]
        tmp_threat_result['action'] = threatmatch.group(3)
        tmp_threat_result['info'] = threatmatch.group(4)
        try:
            # tmp_threat_result['tag'] = '.'.join(tmp_threat_result['name'].replace('a variant of ', '').split('/')[1].split('.')[:-1])
            tmp_threat_result['tag'] = '.'.join(tmp_threat_result['name'].replace('a variant of ', '').split('/')[1].split('.'))
        except Exception as e:
            tmp_threat_result['tag'] = ''

        scan_json['threats'].append(tmp_threat_result)

    return scan_json

def eset_tag(filepath):
    for threat_result in scan_json['threats']:
        if os.path.abspath(threat_result['filename']) == os.path.abspath(filepath):
            return threat_result['tag']

def force_directed_graph(cluster_report, username, password):
    # force directed graph
    cluster_directed = {}
    cluster_directed['nodes'] = []
    cluster_directed['links'] = []
    cluster_directed['tags'] = []
    cluster_id = -1
    for cluster_data in cluster_report['result']:
        cluster_id += 1
        for cluster_name, ssdeep_data in cluster_data.items():
            cluster_nodes = {}
            cluster_nodes['id'] = cluster_name
            cluster_nodes['group'] = cluster_id
            cluster_directed['nodes'].append(cluster_nodes)
            for ssdeep_name, md5_data in ssdeep_data.items():
                nodes_match = False
                for tmp_nodes in cluster_directed['nodes']:
                    # can't understand it
                    # if tmp_nodes['id'] == ssdeep_name and tmp_nodes['group'] == cluster_id:
                    if tmp_nodes['id'] == ssdeep_name:
                        nodes_match = True
                        break
                if not nodes_match:
                    ssdeep_nodes = {}
                    ssdeep_nodes['id'] = ssdeep_name
                    ssdeep_nodes['group'] = cluster_id
                    cluster_directed['nodes'].append(ssdeep_nodes)

                links_match = False
                for tmp_links in cluster_directed['links']:
                    if tmp_links['source'] == ssdeep_name and tmp_links['target'] == cluster_name:
                        links_match = True
                        break
                if not links_match:
                    ssdeep_links = {}
                    ssdeep_links['source'] = ssdeep_name
                    ssdeep_links['target'] = cluster_name
                    cluster_directed['links'].append(ssdeep_links)

                for md5_dict in md5_data:
                    nodes_match = False
                    for tmp_nodes in cluster_directed['nodes']:
                        # can't understand it
                        # if tmp_nodes['id'] == md5_dict['file_md5'] and tmp_nodes['group'] == cluster_id:
                        if tmp_nodes['id'] == str(os.path.basename(md5_dict['file_path'])):
                            nodes_match = True
                            break
                    if not nodes_match:
                        md5_nodes = {}
                        md5_nodes['id'] = str(os.path.basename(md5_dict['file_path']))
                        md5_nodes['group'] = cluster_id
                        cluster_directed['nodes'].append(md5_nodes)

                    links_match = False
                    for tmp_links in cluster_directed['links']:
                        if tmp_links['source'] == str(os.path.basename(md5_dict['file_path'])) and tmp_links['target'] == ssdeep_name:
                            links_match = True
                            break
                    if not links_match:
                        md5_links = {}
                        md5_links['source'] = str(os.path.basename(md5_dict['file_path']))
                        md5_links['target'] = ssdeep_name
                        cluster_directed['links'].append(md5_links)

                    tag_match = False
                    for md5_tag in cluster_directed['tags']:
                        if md5_tag['md5'] == md5_dict['file_md5'] and md5_tag['filename'] == str(os.path.basename(md5_dict['file_path'])):
                            tag_match = True
                            break
                    if not tag_match:
                        tag_dict = {}
                        tag_dict['md5'] = md5_dict['file_md5']
                        tag_dict['filename'] = str(os.path.basename(md5_dict['file_path']))
                        tag_dict['tag'] = md5_dict['tag']
                        cluster_directed['tags'].append(tag_dict)

    base64_data = base64.b64encode(json.dumps(cluster_directed))
    session = str_md5(str(time.time()))
    post_data = {
        "session": session,
        "base64_data": base64_data,
        "type": "set"
    }
    # print post_data
    http_headers = {'Content-Type': 'application/json; charset=utf-8', 'User-Agent': 'FINDMALWARE.ORG'}
    cache_url = "http://192.168.40.156:8081/graph/data/cache_data.php"
    r = requests.post(cache_url, json=post_data, auth=(username, password), headers=http_headers, timeout=30, verify=False)
    if r.status_code == requests.codes.ok:
        # print r.text
        # return session
        j = json.loads(r.text)
        if j['state'] == 'success':
            return session
        else:
            # print r.text
            return None
    else:
        return None

class SSDC():
    def __init__(self, filepath, score, type='file_ssdeep', exclude_files=None):
        self.similar_score = score
        self.hashes = {}
        self.sha256s = {}
        self.integerdb = {}
        self.matches = {}
        self.scores = {}
        self.groups = []
        self.file_lists = []
        self.ssdeep_stats = {}
        self.filepath = filepath
        self.exclude_files = exclude_files
        self.count = 0
        self.cluster_type = type
        self.cluster_report = {}
        self.del_num = 0
        self.ssdeep_sets = set()

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

            elif self.cluster_type == 'code_section_ssdeep':
                section_hash_result = {}
                with open(filepath + file, 'rb') as file1:
                    section_hash_result = get_section_ssdeep(file1)
                if section_hash_result.has_key('.text'):
                    tmp_ssdeep_hash = section_hash_result['.text']

            elif self.cluster_type == 'rodata_section_ssdeep':
                section_hash_result = {}
                with open(filepath + file, 'rb') as file1:
                    section_hash_result = get_section_ssdeep(file1)
                if section_hash_result.has_key('.rodata'):
                    tmp_ssdeep_hash = section_hash_result['.rodata']
                if not tmp_ssdeep_hash:
                    data = os.popen('strings %s' % (filepath + file)).read()
                    tmp_ssdeep_hash = ssdeep.hash(data)

            elif self.cluster_type == 'section_ssdeep':
                section_hash_result = {}
                with open(filepath + file, 'rb') as file1:
                    section_data_result = get_section_data(file1)

                if section_data_result.has_key('.text') and section_data_result.has_key('.rodata'):
                    tmp_ssdeep_hash = ssdeep.hash(section_data_result['.text'] + section_data_result['.rodata'])
                if not tmp_ssdeep_hash:
                    tmp_ssdeep_hash = ssdeep.hash_from_file(filepath + file)

            if not tmp_ssdeep_hash:
                tmp_ssdeep_hash = ssdeep.hash_from_file(filepath + file)

            if tmp_ssdeep_hash:
                self.ssdeep_sets.add(tmp_ssdeep_hash)
                self.count += 1
                if tmp_ssdeep_hash not in self.ssdeep_stats.keys():
                    self.ssdeep_stats[tmp_ssdeep_hash] = []
                tmp_file_ssdeep = {}
                tmp_file_ssdeep['file_path'] = filepath + file
                tmp_file_ssdeep['file_md5'] = file_md5(filepath + file)
                tmp_file_ssdeep['tag'] = eset_tag(filepath + file)
                tmp_file_ssdeep['cluster_type'] = self.cluster_type
                tmp_file_ssdeep['exclude'] = 1 if exclude else 0
                self.ssdeep_stats[tmp_ssdeep_hash].append(tmp_file_ssdeep)

    def cluster_start(self):
        self.gen_ssdeep_hash(self.filepath, exclude=False)

        if self.exclude_files:
            self.gen_ssdeep_hash(self.exclude_files, exclude=True)


    def cluster_finish(self):
        self.gen_cluster_report()

    def handle(self):
        self.cluster_start()
        ssdeep_lists = list(self.ssdeep_sets)

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
                    tmp_file['tag'] = file_ssdeep['tag']
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

    def delete_similars(self, exclude_path=None):
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
                        if exclude_path and exclude_path in tmp_filepaths[i]:
                            pass
                        else:
                            os.remove(tmp_filepaths[i])
                            self.del_num += 1

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
                if flag1 and not flag2:
                    count = 0
                    for file_ssdeep in v:
                        count += 1
                        if count >1:
                            tmp_filepaths.append(file_ssdeep['file_path'])

        # print tmp_filepaths
        tmp_filepaths = list(set(tmp_filepaths))
        for i in range(len(tmp_filepaths)):
            if os.path.exists(tmp_filepaths[i]):
                os.remove(tmp_filepaths[i])
                self.del_num += 1

if __name__ == "__main__":
    starttime = time.time()
    epilogs = "EXAMPLES:\n"
    epilogs += "\tpython ssdc.py /tmp/analysis_samples/ -d -s 0 -e /tmp/exclude_samples/\n"
    epilogs += "\tpython ssdc.py /tmp/analysis_samples/ -d -t imp_exp_ssdeep -s 30 -e /tmp/exclude_samples/\n"
    epilogs += "\tpython ssdc.py /tmp/analysis_samples/ -d -t strings_ssdeep -s 30 -e /tmp/exclude_samples/\n"
    epilogs += "\tpython ssdc.py /tmp/analysis_samples/ -g\n\n"
    epilogs += "Mail bug reports and suggestions to <zom3y3@gmail.com>\n"
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, epilog=epilogs)
    cluster_types = ['file_ssdeep', 'strings_ssdeep', 'imp_exp_ssdeep', 'section_ssdeep', 'code_section_ssdeep', 'rodata_section_ssdeep']
    similar_scores = ['0', '30', '60', '90']
    parser.add_argument(dest='filepath', help='Specific the File Directory')
    parser.add_argument('-c', '--copy', dest='copy', action='store_true', help='Copy the similar files together to a new file directory')
    parser.add_argument('-d', '--delete', dest='delete', action='store_true', help='Delete the similar files')
    parser.add_argument('-g', '--graph', dest='graph', action='store_true', help='Draw Cluster Graph')
    parser.add_argument('-e', '--exclude', dest='exclude', help='Exclude similar files in this file Directory')
    parser.add_argument('-j', '--jsonfile', dest='jsonfile', help='Save cluster json report to this file')
    parser.add_argument('-s', '--score', dest='score', metavar='SCORE', choices=similar_scores, help='Specific the similarity score, list of choices: {%(choices)s}', default='60')
    parser.add_argument('-t', '--type', dest='type', metavar='TYPE', choices=cluster_types, help='Specific the cluster type, list of choices: {%(choices)s}', default='file_ssdeep')

    args = parser.parse_args()

    analysis_path = args.filepath

    if args.score:
        score = int(args.score)
    else:
        score = 60

    if args.type:
        cluetr_type = args.type
    else:
        cluetr_type = 'file_ssdeep'

    if args.exclude:
        exclude_path = args.exclude
    else:
        exclude_path = None

    if args.delete and args.copy:
        print "[+] WARNING: args.delete dosen't work when args.copy is on. "

    filenums = len(os.listdir(analysis_path))
    if not filenums:
        print '> No files, Exit.'
        exit(0)
    print '> Total files num: %d' %(filenums)
    scan_json = eset_scan(analysis_path)
    print '> Clustering ...'
    s = SSDC(analysis_path, score, type=cluetr_type, exclude_files=exclude_path)
    s.handle()
    cluster_report = s.cluster_report
    print s.count
    print '> {0} ssdeep hashes cluster into {1} groups'.format(len(s.hashes), len(s.groups))

    if args.copy:
        timestr = str(int(time.time()))
        for cluster in cluster_report['result']:
            for cluster_name, cluster_data in cluster.items():
                for ssdeep_hash, ssdeep_files in cluster_data.items():
                    for ssdeep_file in ssdeep_files:
                        filedir = '/'.join(ssdeep_file['file_path'].split('/')[0:-1])
                        filename = ssdeep_file['file_path'].split('/')[-1]
                        dst_path = os.path.join(filedir, '%s_%s/%s' % (cluster_report['type'], timestr, cluster_name))
                        dst_file = os.path.join(dst_path, filename)
                        if not os.path.exists(dst_path):
                            os.makedirs(dst_path)
                        shutil.copy(ssdeep_file['file_path'], dst_file)

        print '> Copy the similar files together to %s' %(os.path.join(filedir, '%s_%s/' % (cluster_report['type'], timestr)))

    if args.delete and not args.copy:
        if args.exclude:
            s.delete_exclude()
        s.delete_similars(exclude_path=exclude_path)
        print '> Deleted %d similar files, remaining files num: %d' % (s.del_num, len(os.listdir(analysis_path)))

    if args.jsonfile:
        jsonfile = args.jsonfile
        json_report = json.dumps(s.cluster_report, sort_keys=True, indent=4, separators=(',', ': '))
        f = open(jsonfile, 'w')
        f.write(json_report)
        f.close()
        print '> Save cluster json report to %s' %(jsonfile)
    # print s.cluster_report['result']
    if args.graph and s.cluster_report['result']:
        username, password = 'gr4ph', 'gr4ph'
        #cluster graph
        session = force_directed_graph(s.cluster_report, username, password)
        if session:
            print "> Cluster Graph:", "http://%s:%s@192.168.40.156:8081/graph/graph-directed.php?session=%s" %(username, password, session)
        else:
            print "> Cluster Graph: Not Available!"

    endtime = time.time()
    print '> Time Usage: ' + str(endtime - starttime)

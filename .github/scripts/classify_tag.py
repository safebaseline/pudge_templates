#!/usr/bin/env python3
import os
from pathlib import Path
import shutil
import yaml

poc_type_tags_list = ['rce', 'xss', 'redirect', 'lfi', 'sqli', 'csrf', 'ssrf']
poc_dir_list = ['cves', 'cnvd', 'vulnerabilities']
poc_file_list = []


def tags_list_generator(path):
    tags_list = []
    for site, site_list, file_list in os.walk(path):
        tags_list.append(Path(site).name)
        poc_file_list.extend(file_list)
    return tags_list


def classify_file(file_path, pudge_path):
    tags_list = tags_list_generator(path=pudge_path)
    for site, site_list, file_list in os.walk(file_path):
        for file_name in file_list:
            abs_filename = os.path.abspath(os.path.join(site, file_name))
            if file_name not in poc_file_list and abs_filename.endswith('.yaml') and not file_name.startswith('.'):
                with open(abs_filename, 'r') as y:
                    yaml_template = yaml.safe_load(y)
                    try:
                        tags = set(yaml_template.get('info')['tags'].split(','))
                        print(file_name, tags)
                        poc_tags_set = tags.intersection(tags_list)
                        if poc_tags_set:
                            shutil.copy(abs_filename, os.path.join(pudge_path, str(list(poc_tags_set)[0]), file_name))
                    except KeyError:
                        pass
                        # print(abs_filename)


for poc_dir in poc_dir_list:
    classify_file(file_path="nuclei-templates/" + poc_dir,
                  pudge_path="web/")


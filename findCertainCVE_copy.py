#!/usr/bin/python
# -*- coding: utf-8 -*-

import json 
import os
from collections import defaultdict  #为了实现一个键对应多个值的字典 

CVE_FILE_PATH = [
    "/home/ningan/kdfi/cve/nvdcve-1.1-2019.json",
    "/home/ningan/kdfi/cve/nvdcve-1.1-2018.json",
    "/home/ningan/kdfi/cve/nvdcve-1.1-2017.json",
    "/home/ningan/kdfi/cve/nvdcve-1.1-2016.json",
    "/home/ningan/kdfi/cve/nvdcve-1.1-2015.json",
    "/home/ningan/kdfi/cve/nvdcve-1.1-2014.json",
    "/home/ningan/kdfi/cve/nvdcve-1.1-2013.json",
    "/home/ningan/kdfi/cve/nvdcve-1.1-2012.json",
    "/home/ningan/kdfi/cve/nvdcve-1.1-2011.json",
    "/home/ningan/kdfi/cve/nvdcve-1.1-2010.json"
]




# VULNERABILITY_TYPE = {
#     "integer_overflow" : ["CWE190", "CWE191", "CWE194"],  #CWE190   CWE191
#     "type_conversion" : ["CWE195", "CWE196", "CWE197", "CWE468", "CWE681", "CWE843"],  #CWE681   CWE843
#     "format_string" : ["CWE134", "CWE685", "CWE688"],    #CWE134
#     "use_after_free" : ["CWE416"],  #CWE416
#     "double_free" : ["CWE415"],     #CWE415
#     "memory_leak" : ["CWE401"],
#     "null_pointer_dereference" : ["CWE476", "CWE690"],   #CWE476
#     "use_of_uninitialized_variable" : ["CWE457"],
#     "buffer_overflow" : ["CWE121", "CWE122", "CWE124", "CWE126", "CWE127", "CWE680"],
#     "check_of_return_value" : ["CWE252", "CWE253"]   #CWE252
# }


#  {'CWE476', 'CWE415', 'CWE134', 'CWE681', 'CWE190', 'CWE191', 'CWE843', 'CWE416', 'CWE252'}


VULNERABILITY_TYPE_NVD = {
    "integer_overflow" : ["CWE190", "CWE191"],  #CWE190   CWE191
    "type_conversion" : ["CWE704", "CWE681", "CWE843"],  #CWE681   CWE843
    "format_string" : ["CWE134"],    #CWE134
    "use_after_free" : ["CWE416"],  #CWE416
    "double_free" : ["CWE415"],     #CWE415
    "memory_leak" : ["CWE404", "CWE772"],
    "null_pointer_dereference" : ["CWE476"],   #CWE476
    "use_of_uninitialized_variable" : ["CWE824", "CWE1187"],
    "buffer_overflow" : ["CWE119", "CWE120", "CWE125", "CWE787", "CWE131"],
    "check_of_return_value" : ["CWE252"]   #CWE252
}

#input:CWE-252
#output:CWE252
def cwe_format_change(str):
    str1 = ''
    for i in str:
        if i != "-":
            str1 += i
    return str1



#input:  输入的是nvd下的json文件
#output: 输出的是这些json文件中包括的cve和其对应的cwe的一个字典
#print(json.dumps(find_all_cve_and_corresponding_cwe_from_file(CVE_FILE_PATH),  indent=4))
def find_all_cve_and_corresponding_cwe_from_file(cve_file_path):
    cve_cwe= {}

    #print(os.getcwd())     /home/ningan/kdfi/cve

    for file_path in cve_file_path:

        with open(file_path, 'r', encoding='utf-8') as f:  
            #print("BEGIN %s", file_path)
            strJson = json.load(f)
            # print(type(strJson))   #<class 'dict'>
            # print(strJson["CVE_data_type"])   #CVE
            # print(strJson["CVE_Items"][0]["cve"])
            # print(len(strJson["CVE_Items"]))   #4  #这个长度可以定位到这个文件中有几个cve

            
            for i in range(len(strJson["CVE_Items"])):
                
                cve_id = strJson["CVE_Items"][i]["cve"]["CVE_data_meta"]["ID"]
                if len(strJson["CVE_Items"][i]["cve"]["problemtype"]["problemtype_data"][0]["description"]) == 0: 
                #CVE-2019-0034 特殊情况
                    continue
                else:
                    cwe_id = strJson["CVE_Items"][i]["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
                
                cve_cwe[cve_id] = cwe_format_change(cwe_id)    
    return cve_cwe



#input: 输入的是这些json文件中包括的cve和其对应的cwe的一个字典
#output: 输出的是这些json文件中所包含的cwe和其对应的cve的一个字典
#print(json.dumps(find_all_cve_about_all_cwe(find_all_cve_and_corresponding_cwe_from_file(CVE_FILE_PATH)), indent=4))
def find_all_cve_about_all_cwe(cve_cwe):  #input: 一个关于cve和cwe对应的字典
    cwe_cve = defaultdict(list)
    
    for (cvei, cwei) in cve_cwe.items():    #遍历字典
        cwe_cve[cwei].append(cvei)
    return cwe_cve



#input: 输入的是这些json文件中包括的cve和其对应的cwe的一个字典
#output: 输出的是这些json文件中包括的cwe的一个排序几何
# for i in find_all_cwe_in_nvd(find_all_cve_and_corresponding_cwe_from_file(CVE_FILE_PATH)):
#     print(i)
def find_all_cwe_in_nvd(cve_cwe):
    cwe = set()
    for cwei in cve_cwe.values():
        cwe.add(cwei)
    #return cwe
    return sorted(cwe)



def find_cve_about_memory_safety(cve_cwe, vul_type_nvd):
    cve_about_memory_safety = []

    for (cve, cwe) in cve_cwe.items():    #遍历字典
        for (type_name, cwes) in vul_type_nvd.items():
            for cwei in cwes:
                if cwe in cwei:
                    cve_about_memory_safety.append(cve)

    return cve_about_memory_safety   #返回一个列表



def find_software_and_version_string_of_cve_about_memory_safety(cve_file_path):
    cve_cwe = find_all_cve_and_corresponding_cwe_from_file(CVE_FILE_PATH)
    cve_about_memory_safety = find_cve_about_memory_safety(cve_cwe, VULNERABILITY_TYPE_NVD)  #这是一个列表
    cve_software_name_and_version_str = defaultdict(list) 

    for file_path in cve_file_path:    
        with open(file_path, 'r', encoding='utf-8') as f:  
            #print("BEGIN %s", file_path)
            strJson = json.load(f)            
            for i in range(len(strJson["CVE_Items"])):                
                cve_id = strJson["CVE_Items"][i]["cve"]["CVE_data_meta"]["ID"]
                if cve_id in cve_about_memory_safety:
                    #print("***", cve_id)
                    for j in range(len(strJson["CVE_Items"][i]["configurations"]["nodes"])):  #CVE-2019-16754
                        
                        if strJson["CVE_Items"][i]["configurations"]["nodes"][j]['operator'] == "OR":      
                            if "cpe_match" in strJson["CVE_Items"][i]["configurations"]["nodes"][j]:  #CVE-2019-16754
                                for k in range(len(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"])):
                                    if strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"][k]["vulnerable"] == True:
                                        #print("^^^")
                                        #print(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"][k]["cpe23Uri"])
                                        cve_software_name_and_version_str[cve_id].append(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"][k]["cpe23Uri"])
                                    
                        elif strJson["CVE_Items"][i]["configurations"]["nodes"][j]['operator'] == "AND":
                            if "children" not in strJson["CVE_Items"][i]["configurations"]["nodes"][j]:  #CVE-2019-12217
                                for k in range(len(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"])):
                                    if strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"][k]["vulnerable"] == True:
                                        #print(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"][k]["cpe23Uri"])
                                        cve_software_name_and_version_str[cve_id].append(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"][k]["cpe23Uri"])
                            else:
                                for m in range(len(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["children"])):
                                    for k in range(len(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["children"][m]["cpe_match"])):
                                        if strJson["CVE_Items"][i]["configurations"]["nodes"][j]["children"][m]["operator"] == "OR":
                                            #print("^^^^")

                                            if strJson["CVE_Items"][i]["configurations"]["nodes"][j]["children"][m]["cpe_match"][k]["vulnerable"] == True:
                                                #print(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["children"][m]["cpe_match"][k]["cpe23Uri"])
                                                cve_software_name_and_version_str[cve_id].append(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["children"][m]["cpe_match"][k]["cpe23Uri"])
    
    return cve_software_name_and_version_str


#input:"cpe:2.3:o:microsoft:windows_10:1709:*:*:*:*:*:*:*",
#output:"microsoft:windows_10:1709"
#input:"cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*"
#output:"microsoft:windows_server_2019:-"
def extract_software_name_and_version_from_str(str):
    if str.split(":")[5] != "*":
        return str.split(":")[2] + ":" + str.split(":")[3] + ":" + str.split(":")[4] + ":" + str.split(":")[5] 
    else:
        return str.split(":")[2] + ":" + str.split(":")[3] + ":" +str.split(":")[4]


def statistic_number_of_specific_software_about_memory_safety(cve_file_path):
    cve_software_name_and_version_str = find_software_and_version_string_of_cve_about_memory_safety(cve_file_path)
    software_and_version = []
    software = []
    number_of_software = {}

    for (cve, str_list) in cve_software_name_and_version_str.items():
        for str in str_list:
            software_and_version.append(extract_software_name_and_version_from_str(str))
            software.append(str.split(":")[4])

    software_tmp = software[:]        
    for soft in list(set(software_tmp)):
        number_of_software[soft] = software.count(soft)

    #return software_and_version
    return sorted(number_of_software.items(), key=lambda item:item[1], reverse=True)


def statistic_cve_number_about_vul_type(cve_file_path):
    cve_cwe = find_all_cve_and_corresponding_cwe_from_file(cve_file_path)
    number_of_cve_about_cwe = {}
    cwe_in_cvelist = []
    number_of_cve_about_vul_type = {}

    for (vul, cwes) in VULNERABILITY_TYPE_NVD.items():   #初始化
        number_of_cve_about_vul_type[vul] = 0


    for (cve, cwe) in cve_cwe.items():    #遍历字典
        cwe_in_cvelist.append(cwe)

    cwe_in_cvelist_tmp = cwe_in_cvelist[:]
    for cwei in list(set(cwe_in_cvelist_tmp)):
        number_of_cve_about_cwe[cwei] = cwe_in_cvelist.count(cwei)

    for (cwe, num) in number_of_cve_about_cwe.items():
        for (vul, cwes) in VULNERABILITY_TYPE_NVD.items():
            if cwe in cwes:
                number_of_cve_about_vul_type[vul] += num
    #print()


    #return sorted(number_of_cve_about_cwe.items(), key=lambda item:item[1], reverse=True)
    return sorted(number_of_cve_about_vul_type.items(), key=lambda item:item[1], reverse=True)





def test_find_software_and_version_string_of_cve_about_memory_safety(cve_file_path, software):
    cve_cwe = find_all_cve_and_corresponding_cwe_from_file(CVE_FILE_PATH)
    cve_about_memory_safety = find_cve_about_memory_safety(cve_cwe, VULNERABILITY_TYPE_NVD)  #这是一个列表
    cve_software_name_and_version_str = defaultdict(list) 

    for file_path in cve_file_path:    
        with open(file_path, 'r', encoding='utf-8') as f:  
            #print("BEGIN %s", file_path)
            strJson = json.load(f)            
            for i in range(len(strJson["CVE_Items"])):                
                cve_id = strJson["CVE_Items"][i]["cve"]["CVE_data_meta"]["ID"]
                if cve_id in cve_about_memory_safety:
                    #print("***", cve_id)
                    for j in range(len(strJson["CVE_Items"][i]["configurations"]["nodes"])):  #CVE-2019-16754
                        
                        if strJson["CVE_Items"][i]["configurations"]["nodes"][j]['operator'] == "OR":      
                            if "cpe_match" in strJson["CVE_Items"][i]["configurations"]["nodes"][j]:  #CVE-2019-16754
                                for k in range(len(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"])):
                                    if strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"][k]["vulnerable"] == True:
                                        #print("^^^")
                                        #print(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"][k]["cpe23Uri"])
                                        if strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"][k]["cpe23Uri"].find(software) > 0:
                                            cve_software_name_and_version_str[cve_id].append(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"][k]["cpe23Uri"])
                                    
                        elif strJson["CVE_Items"][i]["configurations"]["nodes"][j]['operator'] == "AND":
                            if "children" not in strJson["CVE_Items"][i]["configurations"]["nodes"][j]:  #CVE-2019-12217
                                for k in range(len(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"])):
                                    if strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"][k]["vulnerable"] == True:
                                        #print(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"][k]["cpe23Uri"])
                                        if strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"][k]["cpe23Uri"].find(software) > 0:
                                            cve_software_name_and_version_str[cve_id].append(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["cpe_match"][k]["cpe23Uri"])
                            else:
                                for m in range(len(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["children"])):
                                    for k in range(len(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["children"][m]["cpe_match"])):
                                        if strJson["CVE_Items"][i]["configurations"]["nodes"][j]["children"][m]["operator"] == "OR":
                                            #print("^^^^")

                                            if strJson["CVE_Items"][i]["configurations"]["nodes"][j]["children"][m]["cpe_match"][k]["vulnerable"] == True:
                                                #print(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["children"][m]["cpe_match"][k]["cpe23Uri"])
                                                if strJson["CVE_Items"][i]["configurations"]["nodes"][j]["children"][m]["cpe_match"][k]["cpe23Uri"].find(software) > 0:
                                                    cve_software_name_and_version_str[cve_id].append(strJson["CVE_Items"][i]["configurations"]["nodes"][j]["children"][m]["cpe_match"][k]["cpe23Uri"])
    
    return cve_software_name_and_version_str




def find_software_and_version_of_cve_of_the_most_vul_about_memory_safety(cve_file_path):
    software = ["chrome", "linux_kernel", "firefox", "seamonkey", "thunderbird", "ntp", "imagemagick", "php", "ffmpeg", "libpng"]
    cve_about_certain_version = find_software_and_version_string_of_cve_about_memory_safety(cve_file_path)
    #print(cve_about_certain_version)
    software_version_num = {}
    sorted_software_version_num = {}
 
    for softwarei in software:
        software_version_num[softwarei] = {}


    for (cve, software_and_version_str) in cve_about_certain_version.items():
        for software_and_version_str_i in software_and_version_str:
            #print(software_and_version_str_i)
            software_name = software_and_version_str_i.split(":")[4]
            software_version = software_and_version_str_i.split(":")[5]            
            if software_name in software:
                software_version_num[software_name][software_version] = 0
                
    for (cve, software_and_version_str) in cve_about_certain_version.items():
        for software_and_version_str_i in software_and_version_str:
            #print(software_and_version_str_i)
            software_name = software_and_version_str_i.split(":")[4]
            software_version = software_and_version_str_i.split(":")[5]
            if software_name in software:                
                software_version_num[software_name][software_version] += 1 
   
    for (softwarei, version_and_number) in software_version_num.items():
        sorted_software_version_num[softwarei] = sort_dict_according_to_value(version_and_number)
        
    return sorted_software_version_num

# "chrome"    4.0.249.78
# "linux_kernel"  3.4
# "firefox"   4.0
# "seamonkey" 2.0
# "thunderbird"   1.5
# "ntp"   4.2.7
# "imagemagick"   7.0.5-5
# "php"   5.6.0
# "ffmpeg"    0.7.1
# "libpng"    1.4.0
    

def sort_dict_according_to_value(dic):
    return sorted(dic.items(), key=lambda item:item[1], reverse=True)




def find_cve_of_the_most_vul_software_version(cve_file_path):
    cve_software_name_and_version_str = find_software_and_version_string_of_cve_about_memory_safety(cve_file_path)
    software_version = ["chrome:4.0.249.78","linux_kernel:3.4","firefox:4.0","seamonkey:2.0","thunderbird:1.5","ntp:4.2.7","imagemagick:7.0.5-5","php:5.6.0","ffmpeg:0.7.1","libpng:1.4.0"]
    cve_of_the_most_vul_software_version = defaultdict(list)

    for (cve, str_list) in cve_software_name_and_version_str.items():
        for str in str_list:
            str_tmp = str.split(":")[4] + ":" + str.split(":")[5]
            for software_version_i in software_version:
                if str_tmp == software_version_i:
                    cve_of_the_most_vul_software_version[software_version_i].append(cve)
    
    for (software_version_i,cve_list) in cve_of_the_most_vul_software_version.items():
        cve_of_the_most_vul_software_version[software_version_i] = list(set(cve_list))

    return  cve_of_the_most_vul_software_version





if __name__ == "__main__":
    
    #print(json.dumps(find_all_cve_and_corresponding_cwe_from_file(CVE_FILE_PATH),  indent=4))

    #print(json.dumps(find_all_cve_about_all_cwe(find_all_cve_and_corresponding_cwe_from_file(CVE_FILE_PATH)), indent=4))

    # for i in find_all_cwe_in_nvd(find_all_cve_and_corresponding_cwe_from_file(CVE_FILE_PATH)):
    #     print(i)

    # for i in find_cve_about_memory_safety(find_all_cve_and_corresponding_cwe_from_file(CVE_FILE_PATH), VULNERABILITY_TYPE_NVD):
    #     print(i)

    #print(json.dumps(find_software_and_version_string_of_cve_about_memory_safety(CVE_FILE_PATH), indent = 4))
    # for i in statistic_number_of_specific_software_about_memory_safety(find_software_and_version_string_of_cve_about_memory_safety(CVE_FILE_PATH)):
    #     print(i)

    
    #print(extract_software_name_and_version_from_str("cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*"))

    # for i in statistic_cve_number_about_vul_type(CVE_FILE_PATH):
    #     print(i)

    #print(find_juliet_cwe_in_cvelist(find_all_cve_and_corresponding_cwe_from_file(CVE_FILE_PATH)))
    #print(json.dumps(test_find_software_and_version_string_of_cve_about_memory_safety(CVE_FILE_PATH, "libpng"), indent = 4))

    #print(json.dumps(find_cve_about_certain_software_and_version_of_cve_about_memory_safety(CVE_FILE_PATH, "libpng:1.0.69"), indent = 4))
    #print(json.dumps(find_cve_about_certain_software_and_version_of_cve_about_memory_safety(CVE_FILE_PATH, "php:7.0.1"), indent = 4))
    print(json.dumps(find_software_and_version_of_cve_of_the_most_vul_about_memory_safety(CVE_FILE_PATH), indent=4))
    
    #print(json.dumps(find_cve_of_the_most_vul_software_version(CVE_FILE_PATH), indent=4))
    


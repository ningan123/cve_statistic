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

CWE_ABOUT_MEMORY_SAFETY = [
    "CWE190", "CWE191", "CWE194", 
    "CWE195", "CWE196", "CWE197", "CWE468", "CWE681", "CWE843",
    "CWE134", "CWE685", "CWE688",
    "CWE416",
    "CWE415",
    "CWE401",
    "CWE476", "CWE690",
    "CWE457",
    "CWE121", "CWE122", "CWE124", "CWE126", "CWE127", "CWE680",
    "CWE252", "CWE253"
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


VULNERABILITY_TYPE = {
    "integer_overflow" : [],  #CWE190   CWE191
    "type_conversion" : [],  #CWE681   CWE843
    "format_string" : [],    #CWE134
    "use_after_free" : [],  #CWE416
    "double_free" : [],     #CWE415
    "memory_leak" : [],
    "null_pointer_dereference" : [],   #CWE476
    "use_of_uninitialized_variable" : ["CWE824"],
    "buffer_overflow" : ["CWE120"],
    "check_of_return_value" : []   #CWE252
}

#input:CWE-252
#output:CWE252
def cwe_format_change(str):
    str1 = ''
    for i in str:
        if i != "-":
            str1 += i
    return str1

def find_cve_related_to_memory_safety(cve_file_path):
    CVE_CWE = {}
    CVE_ABOUT_MEMORY_SAFETY = []

    #print(os.getcwd())     /home/ningan/kdfi/cve
    # os.system(r'flawfinder %s >> %s ' %(tmp, txt_name))
    # os.system(r"touch %s")

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
                #print(cve_id, cwe_id)
                
                CVE_CWE[cve_id] = cwe_id    
            #print(CVE_CWE)   #形成cve cwe键值对

            for (cve, cwe) in CVE_CWE.items():    #遍历字典
                if cwe_format_change(cwe) in CWE_ABOUT_MEMORY_SAFETY:
                    CVE_ABOUT_MEMORY_SAFETY.append(cve)
            #print(CVE_ABOUT_MEMORY_SAFETY)
    return CVE_ABOUT_MEMORY_SAFETY   #返回一个列表





def find_all_cve_and_corresponding_cwe_from_file(cve_file_path):
    cve_cwe= {}

    #print(os.getcwd())     /home/ningan/kdfi/cve
    # os.system(r'flawfinder %s >> %s ' %(tmp, txt_name))
    # os.system(r"touch %s")

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
                #print(cve_id, cwe_id)
                
                cve_cwe[cve_id] = cwe_id    
    return cve_cwe


def find_all_cve_about_certain_cwe_in_memory_safety(cve_cwe):  #input: 一个关于cve和cwe对应的字典
    cve_about_certain_cwe = defaultdict(list)
    

    for (cve, cwe) in cve_cwe.items():    #遍历字典
        cwe = cwe_format_change(cwe)
        if cwe in CWE_ABOUT_MEMORY_SAFETY:
            cve_about_certain_cwe[cwe].append(cve)
    return cve_about_certain_cwe



def find_software_and_version_string(cve_file_path):
    cve_about_memory_safety = find_cve_related_to_memory_safety(CVE_FILE_PATH)  #这是一个列表
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



def statistic_number_of_specific_software(cve_software_name_and_version_str):
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

    # "CVE-2019-0689": [
    #     "cpe:2.3:o:microsoft:windows_10:1709:*:*:*:*:*:*:*",
    #     "cpe:2.3:o:microsoft:windows_10:1803:*:*:*:*:*:*:*",
    #     "cpe:2.3:o:microsoft:windows_10:1809:*:*:*:*:*:*:*",
    #     "cpe:2.3:o:microsoft:windows_server_2016:1709:*:*:*:*:*:*:*",
    #     "cpe:2.3:o:microsoft:windows_server_2016:1803:*:*:*:*:*:*:*",
    #     "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*"
    # ],


#input:"cpe:2.3:o:microsoft:windows_10:1709:*:*:*:*:*:*:*",
#output:"microsoft:windows_10:1709"
#input:"cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*"
#output:"microsoft:windows_server_2019:-"
def extract_software_name_and_version_from_str(str):
    if str.split(":")[5] != "*":
        return str.split(":")[2] + ":" + str.split(":")[3] + ":" + str.split(":")[4] + ":" + str.split(":")[5] 
    else:
        return str.split(":")[2] + ":" + str.split(":")[3] + ":" +str.split(":")[4]



def statistic_cve_number_about_certain_cwe(cve_cwe):
    number_of_cve_about_cwe = {}
    cwe_in_cvelist = []
    number_of_cve_about_vul_type = {}

    for (vul, cwes) in VULNERABILITY_TYPE.items():   #初始化
        number_of_cve_about_vul_type[vul] = 0


    for (cve, cwe) in cve_cwe.items():    #遍历字典
        cwe = cwe_format_change(cwe)
        cwe_in_cvelist.append(cwe)

    cwe_in_cvelist_tmp = cwe_in_cvelist[:]
    for cwei in list(set(cwe_in_cvelist_tmp)):
        number_of_cve_about_cwe[cwei] = cwe_in_cvelist.count(cwei)

    for (cwe, num) in number_of_cve_about_cwe.items():
        for (vul, cwes) in VULNERABILITY_TYPE.items():
            if cwe in cwes:
                number_of_cve_about_vul_type[vul] += num
    #print()


    #return sorted(number_of_cve_about_cwe.items(), key=lambda item:item[1], reverse=True)
    return sorted(number_of_cve_about_vul_type.items(), key=lambda item:item[1], reverse=True)




#def statistic_ratio_of_memory_safety(cve_number_about_cwe):  #输入一个列表

def find_juliet_cwe_in_cvelist(cve_cwe):
    juliet_cwe_in_cvelist = set()
    for (cve, cwe) in cve_cwe.items():    #遍历字典
        cwe = cwe_format_change(cwe)
        if cwe in CWE_ABOUT_MEMORY_SAFETY:
            juliet_cwe_in_cvelist.add(cwe)
    return juliet_cwe_in_cvelist



if __name__ == "__main__":
    #print("&&&&&&&")
    # print(find_cve_related_to_memory_safety(CVE_FILE_PATH))
    
    #print(json.dumps(find_all_cve_and_corresponding_cwe_from_file(CVE_FILE_PATH),  indent=4))
    #print(json.dumps(find_all_cve_about_certain_cwe_in_memory_safety(find_all_cve_and_corresponding_cwe_from_file(CVE_FILE_PATH)), indent=4))
    #print(json.dumps(find_software_and_version_string(CVE_FILE_PATH), indent = 4))
    # for i in statistic_number_of_specific_software(find_software_and_version_string(CVE_FILE_PATH)):
    #     print(i)

    #statistic_number_of_specific_software(find_software_and_version_string(CVE_FILE_PATH))
    #print(extract_software_name_and_version_from_str("cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*"))

    # for i in statistic_cve_number_about_certain_cwe(find_all_cve_and_corresponding_cwe_from_file(CVE_FILE_PATH)):
    #     print(i)
    print(find_juliet_cwe_in_cvelist(find_all_cve_and_corresponding_cwe_from_file(CVE_FILE_PATH)))






# CWE = [
#     "CWE190", "CWE191", "CWE194", 
#     "CWE195", "CWE196", "CWE197", "CWE468", "CWE681", "CWE843",
#     "CWE134", "CWE685", "CWE688",
#     "CWE416",
#     "CWE415",
#     "CWE401",
#     "CWE476", "CWE690",
#     "CWE457",
#     "CWE121", "CWE122", "CWE124", "CWE126", "CWE127", "CWE680",
#     "CWE252", "CWE253"
#     ]
# 3 0-2
# 6 3-8 
# 3 9-11
# 1 12
# 1 13
# 1 14
# 2 15-16
# 1 17
# 6 18-23
# 2 24-25

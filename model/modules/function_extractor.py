# function_extractor.py

import subprocess
import requests
import re
import os

ANSI_ESCAPE = re.compile(r'''
    \x1B    
    (?:     
        [@-Z\\-_]
    |       
        [\x80-\x9A\x9C-\x9F]
    |       
        \[
        [0-?]*  
        [ -/]*  
        [@-~]   
    )
''', re.VERBOSE)


class FunctionExtractor:
    def __init__(self, config_file='4byteConfig.txt'):
        self.config_file = config_file
        self.function_signatures = self.load_function_signatures()

    def read_contract_file(self, file_path):
        if not os.path.exists(file_path):
            print(f"Cannot find file: {file_path}")
            return None
        with open(file_path, 'r') as file:
            return file.read().strip()

    def decompile_contract(self, bytecode):
        process = subprocess.Popen(
            ['panoramix', '-'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(input=bytecode)

        if process.returncode != 0:
            print(f"An error occurred during decompilation: {stderr}")
            return None
        return stdout

    def save_function_signature(self, signature_hash, function_name):
        with open(self.config_file, 'a') as file:
            file.write(f"{signature_hash},{function_name}\n")

    def load_function_signatures(self):
        function_signatures = {}
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as file:
                lines = file.readlines()
                for line in lines:
                    signature_hash, function_name = line.strip().split(',', 1)
                    function_signatures[signature_hash] = function_name
        return function_signatures

    def get_function_name(self, signature_hash):
        if signature_hash in self.function_signatures:
            return self.function_signatures[signature_hash]

        url = f"https://www.4byte.directory/api/v1/signatures/?hex_signature={signature_hash}"
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            if data['count'] > 0:
                function_name = data['results'][data['count'] - 1]['text_signature']
                self.function_signatures[signature_hash] = function_name
                self.save_function_signature(signature_hash, function_name)
                return function_name
        return None

    def replace_unknown_function_names(self, decompiled_code):
        import re

        lines = decompiled_code.splitlines()
        result_lines = []

        for line in lines:
            unknowns = re.findall(r'unknown([0-9a-fA-F]{8})', line)
            if unknowns:
                for hex_signature in unknowns:
                    function_name = self.get_function_name(hex_signature)
                    if function_name:
                        fn_name_only = function_name.split('(')[0]

                        if line.strip().startswith('def unknown' + hex_signature):
                            m_def = re.match(r'(\s*def )unknown' + hex_signature + r'\((.*?)\)(.*)', line)
                            if m_def:
                                indent = m_def.group(1)
                                params_in_def = m_def.group(2)
                                rest_of_line = m_def.group(3)

                                m_fn = re.match(r'([^\(]+)\((.*)\)', function_name)
                                if m_fn:
                                    fn_name = m_fn.group(1)
                                    fn_params = m_fn.group(2)

                                    fn_params_list = [p.strip() for p in fn_params.split(',')] if fn_params else []
                                    fn_param_types = []
                                    fn_param_names = []
                                    for param in fn_params_list:
                                        parts = param.strip().split()
                                        if len(parts) == 2:
                                            param_type, param_name = parts
                                        elif len(parts) == 1:
                                            param_type = parts[0]
                                            param_name = ''
                                        else:
                                            continue 
                                        fn_param_types.append(param_type)
                                        fn_param_names.append(param_name)

                                    params_in_def_list = [p.strip() for p in params_in_def.split(',')] if params_in_def else []
                                    param_names_in_def = []
                                    for param in params_in_def_list:
                                        parts = param.strip().split()
                                        param_name = parts[-1]  
                                        param_names_in_def.append(param_name)


                                    if len(param_names_in_def) == len(fn_param_types):
                                        new_params = []
                                        for param_type, param_name in zip(fn_param_types, param_names_in_def):
                                            new_params.append(f"{param_type} {param_name}")
                                        new_param_str = ', '.join(new_params)
                                        line = f"{indent}{fn_name}({new_param_str}){rest_of_line}"
                                    else:
                                        line = line.replace(f"unknown{hex_signature}", fn_name)
                                else:
                                    line = line.replace(f"unknown{hex_signature}", function_name)
                        else:
                            line = line.replace(f"unknown{hex_signature}", fn_name_only)
            result_lines.append(line)

        return "\n".join(result_lines)

    def clean_ansi_escape_sequences(self, text):
        return ANSI_ESCAPE.sub('', text)

    def extract_functions(self, decompiled_code):
        function_pattern = re.compile(r'^def .+?:', re.MULTILINE)
        matches = list(function_pattern.finditer(decompiled_code))
        functions = []

        for i in range(len(matches)):
            start = matches[i].start()
            if i + 1 < len(matches):
                end = matches[i+1].start()
            else:
                end = len(decompiled_code)
            function_code = decompiled_code[start:end].strip()
            if(function_code.find("def name()") !=-1):
                continue
            elif(function_code.find("def symbol()") !=-1):
                continue
            functions.append(function_code)

        return functions

    def decompile_and_extract(self, bytecode):
        decompiled_code = self.decompile_contract(bytecode)
        if decompiled_code:
            decompiled_code_with_names = self.replace_unknown_function_names(decompiled_code)
            cleaned_code = self.clean_ansi_escape_sequences(decompiled_code_with_names)
            function_list = self.extract_functions(cleaned_code)
            return cleaned_code, function_list
        else:
            print("Failed to decompile the contract.")
            return None, None

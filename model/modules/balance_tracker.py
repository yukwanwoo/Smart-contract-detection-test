#balance_tracker
import re

class BalanceTracker:
    def __init__(self, functions):
        self.functions = functions
        self.storage_variables = {}
        self.balance_variable = None
        self.candidate_functions = []
    
    def extract_storage_variables(self):
        storage_function_str = self.functions[0]
        self.storage_variables = {}
        lines = storage_function_str.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('def storage:'):
                continue
            elif line:
                parts = line.split(' is ')
                if len(parts) == 2:
                    var_name = parts[0].strip()
                    rest = parts[1].strip()
                    var_type = rest.split(' at ')[0].strip()
                    self.storage_variables[var_name] = var_type
        self.extract_balance_variable_from_balanceOf()
        print("Identified balance variable:", self.balance_variable)
    
    def extract_balance_variable_from_balanceOf(self):
        for func in self.functions:
            func_name = self.get_function_name(func)
            if func_name == 'balanceOf':
                lines = func.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith('return '):
                        return_var = line[len('return '):].strip()
                        match = re.match(r'(\w+)\[.*\]', return_var)
                        if match:
                            var_name = match.group(1)
                            if var_name in self.storage_variables:
                                self.balance_variable = var_name
                                break
                        else:
                            if return_var in self.storage_variables:
                                self.balance_variable = return_var
                                break
                break
    
    def analyze_functions(self):
        for idx, func in enumerate(self.functions[1:]):  
            func_name = self.get_function_name(func)
            print(f"Analyzing function {idx+2}: {func_name}")
            has_balance_change = self.check_balance_change(func)
            has_proxy_pattern = self.check_proxy_pattern(func)
            if has_balance_change or has_proxy_pattern:
                print(f"=> Function '{func_name}' has been classified as a candidate function.")
                self.candidate_functions.append(func_name)
    
    def get_function_name(self, func_str):
        lines = func_str.strip().split('\n')
        if lines:
            first_line = lines[0]
            if first_line.startswith('def '):
                func_def = first_line[4:].strip()
                func_name = func_def.split('(')[0]
                return func_name
        return "Unknown"
    
    def check_balance_change(self, func_str):
        balance_change_found = False
        if not self.balance_variable:
            return False  
        lines = func_str.strip().split('\n')
        for line in lines:
            line = line.strip()
            if self.balance_variable in line:
                if re.search(rf'{re.escape(self.balance_variable)}\s*\[.*\](?:\.\w+)*\s*(\+|-)=', line):
                    print(f"  Balance change detected: {line}")
                    balance_change_found = True
                elif re.search(rf'{re.escape(self.balance_variable)}\s*\[.*\](?:\.\w+)*\s*=.*', line):
                    print(f"  Balance assignment detected: {line}")
                    balance_change_found = True
        return balance_change_found
    
    def check_proxy_pattern(self, func_str):
        code_lines = []
        lines = func_str.strip().split('\n')
        for line in lines:
            line = line.split('#')[0]
            code_lines.append(line)
        code_str = '\n'.join(code_lines)

        proxy_patterns = [' CALL ',' call ', 'DELEGATECALL', 'STATICCALL', 'static', 'static call','delegate']
        for pattern in proxy_patterns:
            if pattern in code_str:
                print(f"  Proxy pattern detected: {pattern}")
                return True
        return False

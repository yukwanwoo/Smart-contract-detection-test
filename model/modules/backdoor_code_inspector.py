#backdoor_code_inspector
import re

class BackdoorCodeInspector:
    def __init__(self, functions, balance_variable, candidate_functions):
        self.functions = functions
        self.balance_variable = balance_variable
        self.allowance_variable = None  
        self.candidate_functions = candidate_functions
        self.backdoor_functions = {}
        
        
    def inspect_functions(self):
        transfer_exists = 'transfer' in self.candidate_functions
        self.parse_storage_definitions(self.get_function_by_name("storage"))
        self.extract_allowance_variable_from_allowance()
        
        if transfer_exists:
            func_name = 'transfer'
            func_str = self.get_function_by_name(func_name)
            print(f"Inspecting backdoor in function '{func_name}':")
            self.inspect_function(func_name, func_str)

        for func_name in self.candidate_functions:
            if transfer_exists and func_name == 'transfer':
                continue 
            func_str = self.get_function_by_name(func_name)
            print(f"Inspecting backdoor in function '{func_name}':")
            self.inspect_function(func_name, func_str, transferFunction=False)

    def inspect_function(self, func_name, func_str, transferFunction=True):
        backdoor_types = []
        if self.is_token_generation(func_str):
            backdoor_types.append('Token Generation')
        if self.is_destroy_token(func_str):
            backdoor_types.append('Destroy Token')
        if transferFunction and self.is_transaction_limitation(func_str):
            backdoor_types.append('Transaction Limitation')
        if self.is_funds_manipulation(func_str):
            backdoor_types.append('Funds Manipulation')
        if transferFunction and self.is_fee(func_str):
            backdoor_types.append('Fee')
        if self.is_proxy(func_str):
            backdoor_types.append('Proxy')
        if backdoor_types:
            self.backdoor_functions[func_name] = backdoor_types
            print(f"=> Function '{func_name}' has been classified as backdoor type(s): {backdoor_types}.")
        else:
            print(f"=> Function '{func_name}' has not been classified as a backdoor.")
            
    def parse_storage_definitions(self, storage_str):
        storage_variables = {}
        suspected_blacklist_whitelist_vars = []
        lines = storage_str.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('def storage:'):
                continue  
            if 'is' in line:
                parts = line.split('is')
                var_name = parts[0].strip()
                var_type_info = parts[1].strip()
                storage_variables[var_name] = var_type_info
                if 'mapping of bool' in var_type_info.lower():
                    suspected_blacklist_whitelist_vars.append(var_name)
                elif 'mapping of uint8' in var_type_info.lower():
                    suspected_blacklist_whitelist_vars.append(var_name)
                elif any(keyword in var_name.lower() for keyword in ['blacklist', 'whitelist', 'allowed', 'denied', 'blocked', 'unblocked']):
                    suspected_blacklist_whitelist_vars.append(var_name)
        self.storage_variables = storage_variables
        self.suspected_blacklist_whitelist_vars = suspected_blacklist_whitelist_vars

    def extract_allowance_variable_from_allowance(self):
        for func in self.functions:
            func_name = self.get_function_name(func)
            if func_name.lower() == 'allowance':
                lines = func.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith('return '):
                        return_var = line[len('return '):].strip()
                        match = re.match(r'(\w+)\[.*\]\[.*\]', return_var)
                        if match:
                            var_name = match.group(1)
                            self.allowance_variable = var_name
                            return
                            
        pattern = r'(\w+)\s*\[\s*.*\s*\]\s*\[\s*.*\s*\]\s*(?:\-=\s*|\+=\s*|=\s*|<=|>=|<|>)'
        for func in self.functions:
            matches = re.finditer(pattern, func)
            for match in matches:
                var_name = match.group(1)
                if var_name not in [self.balance_variable, 'totalSupply']:
                    self.allowance_variable = var_name
                    return

    def get_function_by_name(self, func_name):
        for func in self.functions:
            name = self.get_function_name(func)
            if name == func_name:
                return func
        return ""
    
    def get_function_name(self, func_str):
        lines = func_str.strip().split('\n')
        if lines:
            first_line = lines[0]
            if first_line.startswith('def '):
                func_def = first_line[4:].strip()
                func_name = func_def.split('(')[0]
                return func_name
        return "Unknown"
        
    def is_token_generation(self, func_str):
        if not self.balance_variable:
            return False

        variables = self.parse_state_variables(func_str)
        execution_paths = self.parse_control_flow(func_str)

        for path in execution_paths:
            total_increase = 0
            total_decrease = 0
            for line in path:
                line = line.strip()
                increase_match = re.match(rf'{re.escape(self.balance_variable)}\s*\[(.*?)\]\s*\+=\s*(.+)', line)
                if increase_match:
                    addr = increase_match.group(1).strip()
                    amount_str = increase_match.group(2).strip()
                    if addr != '0':  
                        amount_value = self.evaluate_expression(amount_str, variables)
                        total_increase += amount_value
                decrease_match = re.match(rf'{re.escape(self.balance_variable)}\s*\[(.*?)\]\s*\-=\s*(.+)', line)
                if decrease_match:
                    addr = decrease_match.group(1).strip()
                    amount_str = decrease_match.group(2).strip()
                    if addr != '0':  
                        amount_value = self.evaluate_expression(amount_str, variables)
                        total_decrease += amount_value
            if total_increase > total_decrease:
                return True  
        return False  

    def parse_state_variables(self, func_str):
        variables = {}
        pattern = re.compile(r'^\s*(\w+)\s*=\s*(.+)', re.MULTILINE)
        matches = pattern.findall(func_str)
        for var_name, value_str in matches:
            try:
                value = self.evaluate_expression(value_str, {})
                variables[var_name] = value
            except Exception:
                pass 

        parameters = self.extract_function_parameters(func_str)
        for param in parameters:
            variables[param] = 100  

        return variables

    
    def evaluate_expression(self, expr, variables):
        allowed_names = {}
        allowed_names.update(variables)

        try:
            if not re.match(r'^[\d\.\+\-\*/\(\)\s\w]+$', expr):
                raise ValueError('Invalid characters in expression')

            result = eval(expr, {"__builtins__": {}}, allowed_names)
            return result
        except Exception as e:
            return 0  

    def parse_control_flow(self, func_str):
        lines = func_str.strip().split('\n')
        lines = [line.rstrip() for line in lines] 
        return self._parse_block(lines)

    def _parse_block(self, lines, index=0, current_indent=0):
        paths = [[]]
        i = index
        while i < len(lines):
            line = lines[i]
            stripped_line = line.lstrip()
            indent_level = len(line) - len(stripped_line)

            if indent_level < current_indent:
                break

            if stripped_line.startswith('if '):
                condition_block, else_block, next_index = self._parse_if_else(lines, i, indent_level)
                condition_paths = self._parse_block(condition_block, current_indent=indent_level + 4)
                else_paths = self._parse_block(else_block, current_indent=indent_level + 4) if else_block else [[]]
                new_paths = []
                for path in paths:
                    for c_path in condition_paths:
                        new_paths.append(path + c_path)
                    for e_path in else_paths:
                        new_paths.append(path + e_path)
                paths = new_paths
                i = next_index
                continue
            else:
                if indent_level == current_indent:
                    for path in paths:
                        path.append(stripped_line)
                i += 1
        return paths

    def _parse_if_else(self, lines, index, indent_level):
        condition_block = []
        else_block = []
        i = index + 1
        in_else = False
        while i < len(lines):
            line = lines[i]
            current_indent = len(line) - len(line.lstrip())
            stripped_line = line.lstrip()

            if current_indent < indent_level:
                break
            elif stripped_line.startswith('else:') and current_indent == indent_level:
                in_else = True
                i += 1
                continue
            else:
                if in_else:
                    else_block.append(line)
                else:
                    condition_block.append(line)
                i += 1
        return condition_block, else_block, i


    def is_destroy_token(self, func_str):
        if not self.balance_variable:
            return False

        lines = func_str.strip().split('\n')
        has_allowance_check = self.has_allowance_check(func_str)
        decrease=False
        for line in lines:
            line = line.strip()
            assign_match = re.search(rf'{re.escape(self.balance_variable)}\s*\[\s*(.+?)\s*\](?:\.\w+)*\s*([+\-*/%]=|=)\s*(.+)', line)
            if assign_match:
                address = assign_match.group(1)
                operator = assign_match.group(2)
                value_expr = assign_match.group(3)
                
                if ('caller' not in address and 'msg.sender' not in address and 'sender' not in address and address.strip() != '0' and not has_allowance_check):
                    if operator == '-=' or (operator == '=' and self.is_value_decreased(value_expr)):
                        decrease=True
        if decrease:
            for line in lines:
                line = line.strip()
                increase_match = re.match(rf'{re.escape(self.balance_variable)}\s*\[(.+)\]\s*\+=\s*(.+)', line)
                if increase_match:
                    address = increase_match.group(1)
                    if 'caller' not in address and 'msg.sender' not in address and 'sender' not in address and address.strip() != '0' :
                        decrease=False
        return decrease


    def is_value_decreased(self, value_expr):
        value_expr = value_expr.strip()
        if value_expr == '0':
            return True
            
        balance_var_pattern = rf'{re.escape(self.balance_variable)}\s*\[\s*(.+?)\s*\]'
        if re.search(balance_var_pattern, value_expr):
            if any(op in value_expr for op in ['-', '/', '*', '%']):
                return True
        return False

    def has_allowance_check(self, func_str):
        if not self.allowance_variable:
            return False
        comparison_operators = r'(>=|<=|==|!=|>|<)'
        patterns = [
            rf'{re.escape(self.allowance_variable)}\s*\[\s*.*?\s*\]\s*\[\s*.*?\s*\]\s*([+\-*/%]=|=)\s*.*',  
            rf'require\s+.*?\s*{comparison_operators}\s*.*{re.escape(self.allowance_variable)}\s*\[\s*.*?\s*\]\s*\[\s*.*?\s*\]',  
            rf'if\s+.*?\s*{comparison_operators}\s*.*{re.escape(self.allowance_variable)}\s*\[\s*.*?\s*\]\s*\[\s*.*?\s*\]', 
        ]
        for pattern in patterns:
            if re.search(pattern, func_str):
                return True
        return False



    def is_transaction_limitation(self, func_str):
        if 'if' in func_str or 'require' in func_str:
            conditions = self.extract_conditions(func_str)
            parameters = self.extract_function_parameters(func_str)
            for condition in conditions:
                variables = self.extract_variables(condition)
                general_conditions = [
                    cond for cond in [
                        self.balance_variable, self.allowance_variable, 'totalSupply', 'overflow', 'underflow', 'msg.sender',
                        'address', 'require', 'revert',
                        'recipient', 'sender', 'spender', 'owner',
                        'caller', 'this'
                    ] if cond is not None
                ] + parameters  
                non_standard_vars = [var for var in variables if var not in general_conditions]
                if len(non_standard_vars) > 0:
                    var = non_standard_vars[0]
                    if var in self.storage_variables:
                        var_type = self.storage_variables[var]
                        if 'bool' in var_type.lower() or 'uint8' in var_type.lower():
                            print(f"  Transaction Limitation pattern found.")
                            return True

                variables_set = set(variables)
                general_conditions_set = set(general_conditions)
                if self.is_blacklist_whitelist_condition(condition):
                    print(f"  Transaction Limitation pattern found.")
                    return True
                if variables_set - general_conditions_set:
                    if self.is_balance_limited_condition(condition):
                        if not self.is_overflow_underflow_check(condition):
                            print(f"  Transaction Limitation pattern found.")
                            return True
                    elif self.is_transfer_amount_limited_condition(condition, parameters):
                        if not self.is_overflow_underflow_check(condition):
                            print(f"  Transaction Limitation pattern found.")
                            return True

        return False

    def extract_conditions(self, func_str):
        conditions = []
        lines = func_str.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('if '):
                condition_start = line.find('if ') + 3 
                condition_end = line.find(':')
                if condition_end == -1:
                    condition_end = len(line)
                condition = line[condition_start:condition_end].strip()
                conditions.append(condition)
            elif line.startswith('require'):
                condition_start = line.find('(') + 1
                condition_end = line.rfind(')')
                if condition_start > 0 and condition_end > condition_start:
                    condition = line[condition_start:condition_end].strip()
                else:
                    condition_start = line.find('require') + len('require')
                    condition = line[condition_start:].strip()
                conditions.append(condition)
        return conditions

    def extract_variables(self, condition):
        tokens = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', condition)
        operators = {'and', 'or', 'not', 'in', 'is', '==', '!=', '<', '>', '<=', '>=', '+', '-', '*', '/', '%', '(', ')', '[', ']', '.', ',', ' ', '', 'return', 'if', 'require', 'else'}
        variables = [token for token in tokens if token not in operators and not token.isdigit()]
        return variables

    def is_balance_limited_condition(self, condition):
        pattern = rf'{re.escape(self.balance_variable)}\s*\[\s*(?:caller|msg\.sender)\s*\]\s*([<>=!]+)\s*(.+)'
        match = re.search(pattern, condition)
        if match:
            return True
        return False

    def is_transfer_amount_limited_condition(self, condition, parameters):
        transfer_amount_params = ['_param2', 'amount', 'value', 'amt', 'tokens']
        for param in transfer_amount_params:
            if param in parameters:
                pattern = rf'{param}\s*([<>=!]+)\s*(.+)'
                match = re.search(pattern, condition)
                if match:
                    return True
        return False

    def is_overflow_underflow_check(self, condition):
        overflow_patterns = [
            rf'{re.escape(self.balance_variable)}\s*\[\s*(?:caller|msg\.sender)\s*\]\s*>=\s*{re.escape(self.transfer_amount_parameter)}',
            rf'{re.escape(self.balance_variable)}\s*\[\s*(?:caller|msg\.sender)\s*\]\s*-\s*{re.escape(self.transfer_amount_parameter)}\s*>=\s*0',
            rf'{re.escape(self.balance_variable)}\s*\[\s*.*?\s*\]\s*\+\s*{re.escape(self.transfer_amount_parameter)}\s*>=\s*{re.escape(self.balance_variable)}\s*\[\s*.*?\s*\]',
            rf'{re.escape(self.balance_variable)}\s*\[\s*.*?\s*\]\s*\+\s*{re.escape(self.transfer_amount_parameter)}\s*>=\s*{re.escape(self.transfer_amount_parameter)}'
        ]
        for pattern in overflow_patterns:
            if re.match(pattern, condition):
                return True
        return False

    def is_blacklist_whitelist_condition(self, condition):
        variables = self.extract_variables(condition)
        for var in variables:
            if var in self.suspected_blacklist_whitelist_vars:
                return True
        return False
    
    def extract_function_parameters(self, func_str):
        parameters = []
        lines = func_str.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('def '):
                start_idx = line.find('(')
                end_idx = line.find(')')
                if start_idx != -1 and end_idx != -1:
                    params_str = line[start_idx+1:end_idx]
                    params_list = params_str.split(',')
                    for param in params_list:
                        param = param.strip()
                        if param:
                            param_parts = param.split()
                            if len(param_parts) >= 2:
                                param_type = param_parts[0]
                                param_name = param_parts[1]
                            else:
                                param_type = None
                                param_name = param_parts[0]
                            parameters.append(param_name)
                            if param_name not in self.storage_variables and param_type == 'uint256':
                                self.transfer_amount_parameter = param_name
                break  
        return parameters


    
    def is_funds_manipulation(self, func_str):
        if not self.balance_variable:
            return False
        has_balance_decrease = False
        lines = func_str.strip().split('\n')
        for line in lines:
            line = line.strip()
            decrease_match = re.match(rf'{re.escape(self.balance_variable)}\s*\[.*\]\s*\-=\s*(.+)', line)
            if decrease_match:
                has_balance_decrease = True
                break
        if not has_balance_decrease:
            return False
        caller_balance_decreased = self.has_caller_balance_decrease(func_str)
        has_allowance_check = self.has_allowance_check(func_str)
        for line in lines:
            line = line.strip()
            increase_match = re.match(rf'{re.escape(self.balance_variable)}\s*\[(.+)\]\s*\+=\s*(.+)', line)
            if increase_match:
                address = increase_match.group(1)
                if 'caller' not in address and not caller_balance_decreased and not has_allowance_check:
                    print(f"  Funds Manipulation pattern found: {line}")
                    return True
        return False
    
    def has_caller_balance_decrease(self, func_str):
        pattern = rf'{re.escape(self.balance_variable)}\s*\[.*caller.*\]\s*\-='
        if re.search(pattern, func_str):
            return True
        return False
        
    def is_fee(self, func_str):
        if not self.balance_variable:
            return False

        variables = self.parse_state_variables(func_str)
        sender_decrease_expr = None
        recipient_increase_expr = None

        lines = func_str.strip().split('\n')
        for line in lines:
            line = line.strip()
            match_decrease = re.match(
                rf'{re.escape(self.balance_variable)}\s*\[\s*(?:caller|msg\.sender)\s*\]\s*\-=\s*(.+)', line
            )
            if match_decrease:
                sender_decrease_expr = match_decrease.group(1).strip()

            match_increase = re.match(
                rf'{re.escape(self.balance_variable)}\s*\[\s*(?:address\((.+?)\)|(.+?))\s*\]\s*\+\=\s*(.+)', line
            )
            if match_increase:
                address = match_increase.group(1) or match_increase.group(2)
                address = address.strip()
                if address != 'caller' and address != 'msg.sender':
                    recipient_increase_expr = match_increase.group(3).strip()

        if sender_decrease_expr and recipient_increase_expr:
            sender_decrease = self.evaluate_expression(sender_decrease_expr, variables)
            recipient_increase = self.evaluate_expression(recipient_increase_expr, variables)
            if sender_decrease > recipient_increase:
                print(f"  Proxy pattern found.")
                return True
        return False



    
    def is_proxy(self, func_str):
        delegate_patterns=[ 'DELEGATE','delegate' ]
        for pattern in delegate_patterns:
            if pattern in func_str:
                print(f"  Proxy pattern found: {pattern}")
                return True

        proxy_patterns = [' CALL ', ' call ', 'STATIC','STATIC CALL', 'static', 'static call']
        for pattern in proxy_patterns:
            if pattern in func_str:
                if self.has_state_change_after_call(func_str, pattern):
                    print(f"  Proxy pattern found: {pattern}")
                    return True
        return False
    
    def has_state_change_after_call(self, func_str, call_type):
        lines = func_str.strip().split('\n')
        call_found = False
        for line in lines:
            line = line.strip()
            if call_type in line:
                call_found = True
            elif call_found:
                if any(op in line for op in ['+=', '-=', '=']):
                    return True
        return False

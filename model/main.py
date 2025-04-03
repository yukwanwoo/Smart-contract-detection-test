from modules.function_extractor import FunctionExtractor
from modules.balance_tracker import BalanceTracker
from modules.backdoor_code_inspector import BackdoorCodeInspector



CONTRACT_FILE = './tokenCode/evalData/compiled/destroy/BabyProfofinu/BabyProfofinu.bytecode'




if __name__ == "__main__":
    extractor = FunctionExtractor()
    bytecode = extractor.read_contract_file(CONTRACT_FILE)
    if bytecode:
        full_code, functions = extractor.decompile_and_extract(bytecode)
        if full_code and functions:
            tracker = BalanceTracker(functions)
            tracker.extract_storage_variables()
            tracker.analyze_functions()
            inspector = BackdoorCodeInspector(functions, tracker.balance_variable, tracker.candidate_functions)
            inspector.inspect_functions()
            print("Backdoor functions detected:")
            for func_name, types in inspector.backdoor_functions.items():
                print(f"- '{func_name}': {types}")

        else:
            print("Failed to extract the function.")
    else:
        print("Failed to read bytecode from the file.")

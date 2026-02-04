import sys
import os
from src.generate_cso_attacker.generate_CSO_attacker_entry import CSO_Attacker_Generator
from utils.tools import Tools   


sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))    
def run_cso_attacker_generation():
    # 在运行生成器之前清空cso-attacker目录
    cso_attacker_dir = "resources/cso-attacker"
    print(f"正在清空 {cso_attacker_dir} 目录...")
    Tools.clear_directory(cso_attacker_dir)
    print("目录已清空，开始运行CSO攻击者生成器...")
    CSO_Attacker_Generator.generate_cso_attacker()

if __name__ == "__main__":
    run_cso_attacker_generation()
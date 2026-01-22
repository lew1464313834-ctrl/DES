import sys
import os
from src.generate_cso_attacker.generate_CSO_attacker_entry import CSO_Attacker_Generator
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))    
def run_cso_attacker_generation():
    CSO_Attacker_Generator.generate_cso_attacker()

if __name__ == "__main__":
    run_cso_attacker_generation()
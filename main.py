import sys
import os
import shutil
from pathlib import Path
from src.generate_cso_attacker.generate_CSO_attacker_entry import CSO_Attacker_Generator   
def clear_directory(directory_path):
    """
    清空指定目录中的所有文件和子目录
    
    Args:
        directory_path (str): 要清空的目录路径
    
    Returns:
        bool: 清理操作是否成功
    """
    try:
        dir_path = Path(directory_path)
        
        # 如果目录不存在，创建它
        dir_path.mkdir(parents=True, exist_ok=True)
        
        # 遍历目录中的所有文件和子目录
        for item in dir_path.iterdir():
            if item.is_file():
                # 删除文件
                item.unlink()
                print(f"已删除文件: {item}")
            elif item.is_dir():
                # 如果是子目录，则递归删除整个子目录
                shutil.rmtree(item)
                print(f"已删除目录: {item}")
        
        print(f"目录 {directory_path} 已清空")
        return True
    except Exception as e:
        print(f"清空目录时发生错误: {e}")
        return False

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))    
def run_cso_attacker_generation():
    # 在运行生成器之前清空cso-attacker目录
    cso_attacker_dir = "resources/cso-attacker"
    print(f"正在清空 {cso_attacker_dir} 目录...")
    clear_directory(cso_attacker_dir)
    print("目录已清空，开始运行CSO攻击者生成器...")
    CSO_Attacker_Generator.generate_cso_attacker()

if __name__ == "__main__":
    run_cso_attacker_generation()
import shutil
from pathlib import Path

def clean_all_logs(logs_directory="logs"):
    """
    清除指定目录下的所有日志文件
    
    Args:
        logs_directory (str): 日志目录路径，默认为 'logs'
    
    Returns:
        bool: 清理操作是否成功
    """
    try:
        log_dir = Path(logs_directory)
        
        # 检查日志目录是否存在
        if not log_dir.exists():
            print(f"日志目录 {logs_directory} 不存在")
            return True  # 如果目录不存在，认为已经清理完成
        
        # 遍历日志目录中的所有文件和子目录
        for item in log_dir.iterdir():
            if item.is_file() and item.suffix.lower() in ['.log']:
                # 删除日志文件
                item.unlink()
                print(f"已删除日志文件: {item}")
            elif item.is_dir():
                # 如果是子目录，则递归删除整个子目录
                shutil.rmtree(item)
                print(f"已删除日志目录: {item}")
        
        print("所有日志文件已清除完毕")
        return True
    except Exception as e:
        print(f"清除日志时发生错误: {e}")
        return False

def clean_logs_by_logger_patterns(logger_name_prefix="", logs_directory="logs"):
    """
    根据logger名称模式清除对应的日志文件
    
    Args:
        logger_name_prefix (str): logger名称前缀，留空则匹配所有logger
        logs_directory (str): 日志目录路径，默认为 'logs'
    
    Returns:
        bool: 清理操作是否成功
    """
    try:
        log_dir = Path(logs_directory)
        
        if not log_dir.exists():
            print(f"日志目录 {logs_directory} 不存在")
            return True
        
        # 定义日志级别模式
        log_levels = ['info', 'debug', 'warning', 'error', 'critical']
        
        # 构建要匹配的文件模式
        for level in log_levels:
            if logger_name_prefix:
                pattern = f"{logger_name_prefix}*_{level}.log"
            else:
                pattern = f"*_{level}.log"
            
            # 查找并删除匹配的日志文件
            for log_file in log_dir.glob(pattern):
                if log_file.is_file():
                    log_file.unlink()
                    print(f"已删除日志文件: {log_file}")
        
        return True
    except Exception as e:
        print(f"按模式清除日志时发生错误: {e}")
        return False

if __name__ == "__main__":
    # 示例：清除所有日志
    print("开始清除所有日志...")
    clean_all_logs()
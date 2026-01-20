import logging
from datetime import datetime
from pathlib import Path

class Logger:
    """
    日志工具类，支持将日志信息记录到不同文件
    """
    
    def __init__(self, logger_name="default_logger", base_log_dir="logs", level=logging.INFO):
        """
        初始化日志记录器
        
        Args:
            logger_name (str): 日志记录器名称
            base_log_dir (str): 基础日志目录，默认为 'logs'
            level: 日志级别，默认为 INFO
        """
        self.logger_name = logger_name
        self.level = level
        self.base_log_dir = Path(base_log_dir)
        self.base_log_dir.mkdir(exist_ok=True)  # 创建基础日志目录
        
        # 为不同的日志级别创建不同的文件
        self.log_files = {
            'info': self.base_log_dir / f"{logger_name}_info.log",
            'debug': self.base_log_dir / f"{logger_name}_debug.log", 
            'warning': self.base_log_dir / f"{logger_name}_warning.log",
            'error': self.base_log_dir / f"{logger_name}_error.log",
            'critical': self.base_log_dir / f"{logger_name}_critical.log"
        }
        
        # 为每个日志级别创建独立的logger
        self.loggers = {}
        for level_name, log_file in self.log_files.items():
            self.loggers[level_name] = self._create_logger_for_level(level_name, log_file)
    
    def _create_logger_for_level(self, level_name, log_file):
        """为特定日志级别创建logger"""
        logger = logging.getLogger(f"{self.logger_name}_{level_name}")
        logger.setLevel(self.level)
        
        # 清除已有处理器
        logger.handlers.clear()
        
        # 创建文件处理器
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        file_handler.setLevel(self.level)
        
        # 创建格式化器
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def info(self, message):
        """
        记录 INFO 级别日志到 info 文件
        
        Args:
            message (str): 日志消息
        """
        self.loggers['info'].info(message)
    
    def debug(self, message):
        """
        记录 DEBUG 级别日志到 debug 文件
        
        Args:
            message (str): 日志消息
        """
        self.loggers['debug'].debug(message)
    
    def warning(self, message):
        """
        记录 WARNING 级别日志到 warning 文件
        
        Args:
            message (str): 日志消息
        """
        self.loggers['warning'].warning(message)
    
    def error(self, message):
        """
        记录 ERROR 级别日志到 error 文件
        
        Args:
            message (str): 日志消息
        """
        self.loggers['error'].error(message)
    
    def critical(self, message):
        """
        记录 CRITICAL 级别日志到 critical 文件
        
        Args:
            message (str): 日志消息
        """
        self.loggers['critical'].critical(message)
    
    def get_log_file_path(self, level_name):
        """
        获取指定级别的日志文件路径
        
        Args:
            level_name (str): 日志级别名称 ('info', 'debug', 'warning', 'error', 'critical')
        
        Returns:
            Path: 日志文件路径
        """
        return self.log_files.get(level_name)


# 创建全局日志实例的便捷函数
def get_logger(logger_name="app_logger", base_log_dir="logs"):
    """
    获取日志记录器实例
    
    Args:
        logger_name (str): 日志记录器名称
        base_log_dir (str): 基础日志目录
    
    Returns:
        Logger: 日志记录器实例
    """
    return Logger(logger_name, base_log_dir)


# 全局默认日志记录器
_default_logger = Logger()

def log_info(message, logger_name="default", base_log_dir="logs"):
    """
    便捷函数：直接记录 INFO 级别日志到对应文件
    
    Args:
        message (str): 日志消息
        logger_name (str): 日志记录器名称
        base_log_dir (str): 基础日志目录
    """
    temp_logger = Logger(logger_name=logger_name, base_log_dir=base_log_dir)
    temp_logger.info(message)


def log_error(message, logger_name="default", base_log_dir="logs"):
    """
    便捷函数：直接记录 ERROR 级别日志到对应文件
    
    Args:
        message (str): 日志消息
        logger_name (str): 日志记录器名称
        base_log_dir (str): 基础日志目录
    """
    temp_logger = Logger(logger_name=logger_name, base_log_dir=base_log_dir)
    temp_logger.error(message)


def log_warning(message, logger_name="default", base_log_dir="logs"):
    """
    便捷函数：直接记录 WARNING 级别日志到对应文件
    
    Args:
        message (str): 日志消息
        logger_name (str): 日志记录器名称
        base_log_dir (str): 基础日志目录
    """
    temp_logger = Logger(logger_name=logger_name, base_log_dir=base_log_dir)
    temp_logger.warning(message)


def log_debug(message, logger_name="default", base_log_dir="logs"):
    """
    便捷函数：直接记录 DEBUG 级别日志到对应文件
    
    Args:
        message (str): 日志消息
        logger_name (str): 日志记录器名称
        base_log_dir (str): 基础日志目录
    """
    temp_logger = Logger(logger_name=logger_name, base_log_dir=base_log_dir)
    temp_logger.debug(message)


def log_critical(message, logger_name="default", base_log_dir="logs"):
    """
    便捷函数：直接记录 CRITICAL 级别日志到对应文件
    
    Args:
        message (str): 日志消息
        logger_name (str): 日志记录器名称
        base_log_dir (str): 基础日志目录
    """
    temp_logger = Logger(logger_name=logger_name, base_log_dir=base_log_dir)
    temp_logger.critical(message)
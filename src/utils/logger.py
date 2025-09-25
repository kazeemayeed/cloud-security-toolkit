"""
Logging configuration
"""

import logging
import sys
from typing import Optional


def setup_logger(verbose: bool = False, log_file: Optional[str] = None) -> logging.Logger:
    """Setup application logger"""
    
    # Create logger
    logger = logging.getLogger('cloud_security_toolkit')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Remove existing handlers
    for handler in logger.handlers:
        logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger() -> logging.Logger:
    """Get the application logger"""
    return logging.getLogger('cloud_security_toolkit')

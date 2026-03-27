import json
import logging
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path

import yaml

from .security_utils import safe_load_file, MAX_CONFIG_FILE_SIZE

logger = logging.getLogger(__name__)


def validate_mcp_config_structure(config: Dict[str, Any], file_path: str) -> List[str]:
    errors = []
    
    if not isinstance(config, dict):
        errors.append(f"Configuration file '{file_path}' must contain a JSON/YAML object")
        return errors
    
    has_servers = 'mcpServers' in config or 'servers' in config
    
    if not has_servers and not isinstance(config, dict):
        errors.append(f"Configuration file '{file_path}' must contain 'mcpServers' or 'servers' key, or be a server configuration object")
    
    if has_servers:
        servers_key = 'mcpServers' if 'mcpServers' in config else 'servers'
        servers = config.get(servers_key)
        
        if not isinstance(servers, dict):
            errors.append(f"'{servers_key}' in '{file_path}' must be an object/dictionary")
        elif len(servers) == 0:
            errors.append(f"'{servers_key}' in '{file_path}' is empty - no servers configured")
        else:
            for server_name, server_config in servers.items():
                if not isinstance(server_config, dict):
                    errors.append(f"Server '{server_name}' in '{file_path}' must be a configuration object")
                else:
                    if 'command' not in server_config and 'url' not in server_config and 'endpoint' not in server_config:
                        errors.append(
                            f"Server '{server_name}' in '{file_path}' must have at least one of: 'command', 'url', or 'endpoint'"
                        )
    
    return errors


def load_and_validate_config(file_path: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    errors = []
    config = None
    
    if not Path(file_path).exists():
        errors.append(f"Configuration file '{file_path}' does not exist")
        return None, errors
    
    try:
        config = safe_load_file(Path(file_path), MAX_CONFIG_FILE_SIZE)
    except ValueError as e:
        errors.append(str(e))
        return None, errors
    except json.JSONDecodeError as e:
        errors.append(f"Invalid JSON in '{file_path}': {e}")
        return None, errors
    except yaml.YAMLError as e:
        errors.append(f"Invalid YAML in '{file_path}': {e}")
        return None, errors
    except Exception as e:
        errors.append(f"Error reading '{file_path}': {e}")
        return None, errors
    
    if config is None:
        errors.append(f"Configuration file '{file_path}' is empty")
        return None, errors
    
    validation_errors = validate_mcp_config_structure(config, file_path)
    errors.extend(validation_errors)
    
    return config, errors


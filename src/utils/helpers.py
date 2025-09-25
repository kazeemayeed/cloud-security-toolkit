"""
Helper utilities
"""

import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from file or return defaults"""
    
    default_config = {
        'analysis': {
            'severity_threshold': 'medium',
            'output_format': 'json',
            'auto_remediate': False
        },
        'rules': {
            'aws': ['encryption_at_rest', 'public_access', 'iam_permissions'],
            'azure': ['network_security', 'storage_security'],
            'gcp': ['compute_security', 'storage_security']
        },
        'remediation': {
            'create_backup': True,
            'backup_suffix': '.backup'
        }
    }
    
    if not config_path:
        # Try to find config file in common locations
        possible_paths = [
            'config/settings.yaml',
            'settings.yaml',
            '.cloud-security-toolkit.yaml'
        ]
        
        for path in possible_paths:
            if Path(path).exists():
                config_path = path
                break
    
    if config_path and Path(config_path).exists():
        try:
            with open(config_path, 'r') as f:
                if config_path.endswith('.json'):
                    file_config = json.load(f)
                else:
                    file_config = yaml.safe_load(f)
            
            # Merge with defaults
            return merge_configs(default_config, file_config)
        except Exception as e:
            print(f"Warning: Failed to load config from {config_path}: {e}")
    
    return default_config


def merge_configs(default: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge configuration dictionaries"""
    result = default.copy()
    
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_configs(result[key], value)
        else:
            result[key] = value
    
    return result


def save_report(results: Dict[str, Any], output_path: str) -> None:
    """Save analysis results to file"""
    output_file = Path(output_path)
    
    # Determine format from extension
    if output_file.suffix.lower() == '.json':
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    
    elif output_file.suffix.lower() in ['.yaml', '.yml']:
        with open(output_file, 'w') as f:
            yaml.dump(results, f, default_flow_style=False)
    
    elif output_file.suffix.lower() == '.html':
        generate_html_report(results, output_file)
    
    else:
        # Default to JSON
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)


def generate_html_report(results: Dict[str, Any], output_file: Path) -> None:
    """Generate HTML report from analysis results"""
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cloud Security Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .header { background-color: #f0f0f0; padding: 20px; margin-bottom: 20px; }
            .summary { display: flex; gap: 20px; margin-bottom: 30px; }
            .metric { background-color: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
            .critical { border-left: 5px solid #dc3545; }
            .high { border-left: 5px solid #fd7e14; }
            .medium { border-left: 5px solid #ffc107; }
            .low { border-left: 5px solid #28a745; }
            .finding { margin: 10px 0; padding: 15px; border-radius: 5px; }
            .finding h4 { margin: 0 0 10px 0; }
            .finding-details { font-size: 0.9em; color: #666; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Cloud Security Analysis Report</h1>
            <p>Generated: {timestamp}</p>
        </div>
        
        <div class="summary">
            <div class="metric">
                <h3>Files Analyzed</h3>
                <p style="font-size: 2em; margin: 0;">{files_analyzed}</p>
            </div>
            <div class="metric">
                <h3>Total Issues</h3>
                <p style="font-size: 2em; margin: 0;">{total_issues}</p>
            </div>
            <div class="metric critical">
                <h3>Critical</h3>
                <p style="font-size: 2em; margin: 0;">{critical}</p>
            </div>
            <div class="metric high">
                <h3>High</h3>
                <p style="font-size: 2em; margin: 0;">{high}</p>
            </div>
            <div class="metric medium">
                <h3>Medium</h3>
                <p style="font-size: 2em; margin: 0;">{medium}</p>
            </div>
            <div class="metric low">
                <h3>Low</h3>
                <p style="font-size: 2em; margin: 0;">{low}</p>
            </div>
        </div>
        
        <div class="findings">
            <h2>Findings</h2>
            {findings_html}
        </div>
    </body>
    </html>
    """
    
    # Generate findings HTML
    findings_html = ""
    for finding in results.get('findings', []):
        severity = finding.get('severity', 'medium').lower()
        findings_html += f"""
        <div class="finding {severity}">
            <h4>{finding.get('rule_name', 'Unknown Rule')}</h4>
            <p><strong>File:</strong> {finding.get('file', 'Unknown')}</p>
            <p><strong>Resource:</strong> {finding.get('resource', 'Unknown')}</p>
            <p><strong>Message:</strong> {finding.get('message', 'No message')}</p>
            <div class="finding-details">
                <p><strong>Severity:</strong> {severity.title()}</p>
                <p><strong>Category:</strong> {finding.get('category', 'Unknown')}</p>
                <p><strong>Line:</strong> {finding.get('line', 'Unknown')}</p>
            </div>
        </div>
        """
    
    # Format the HTML
    html_content = html_template.format(
        timestamp=results.get('timestamp', 'Unknown'),
        files_analyzed=results.get('summary', {}).get('files_analyzed', 0),
        total_issues=results.get('summary', {}).get('total_issues', 0),
        critical=results.get('summary', {}).get('critical', 0),
        high=results.get('summary', {}).get('high', 0),
        medium=results.get('summary', {}).get('medium', 0),
        low=results.get('summary', {}).get('low', 0),
        findings_html=findings_html
    )
    
    with open(output_file, 'w') as f:
        f.write(html_content)


def format_finding_for_console(finding: Dict[str, Any]) -> str:
    """Format a finding for console output"""
    severity_colors = {
        'critical': '\033[91m',  # Red
        'high': '\033[93m',      # Yellow
        'medium': '\033[94m',    # Blue
        'low': '\033[92m',       # Green
    }
    
    reset_color = '\033[0m'
    severity = finding.get('severity', 'medium').lower()
    color = severity_colors.get(severity, '')
    
    return f"{color}[{severity.upper()}]{reset_color} {finding.get('file', 'Unknown')}:{finding.get('line', '?')} - {finding.get('message', 'No message')}"

### src/core/rule_engine.py
```python
"""
Rule engine for evaluating security rules
"""

from typing import Dict, List, Any
from pathlib import Path


class RuleEngine:
    def __init__(self):
        self.severity_weights = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
    
    def evaluate_rule(self, rule: Dict[str, Any], content: Dict[str, Any], 
                     file_path: Path) -> List[Dict[str, Any]]:
        """Evaluate a single rule against parsed content"""
        findings = []
        
        try:
            # Get the rule evaluation function
            evaluate_func = rule.get('evaluate')
            if not evaluate_func:
                return findings
            
            # Execute the rule
            violations = evaluate_func(content)
            
            # Convert violations to findings
            for violation in violations:
                finding = {
                    'file': str(file_path),
                    'rule_id': rule.get('id'),
                    'rule_name': rule.get('name'),
                    'severity': rule.get('severity', 'medium'),
                    'category': rule.get('category'),
                    'message': violation.get('message', rule.get('description')),
                    'line': violation.get('line', 1),
                    'column': violation.get('column', 1),
                    'resource': violation.get('resource'),
                    'fix_suggestion': rule.get('fix_suggestion'),
                    'references': rule.get('references', [])
                }
                findings.append(finding)
                
        except Exception as e:
            # If rule evaluation fails, create an error finding
            findings.append({
                'file': str(file_path),
                'rule_id': rule.get('id', 'unknown'),
                'rule_name': rule.get('name', 'Unknown Rule'),
                'severity': 'medium',
                'category': 'rule_error',
                'message': f"Rule evaluation failed: {str(e)}",
                'line': 1,
                'column': 1
            })
        
        return findings
    
    def filter_by_severity(self, findings: List[Dict[str, Any]], 
                          min_severity: str) -> List[Dict[str, Any]]:
        """Filter findings by minimum severity level"""
        min_weight = self.severity_weights.get(min_severity, 2)
        
        return [
            finding for finding in findings
            if self.severity_weights.get(finding.get('severity', 'medium'), 2) >= min_weight
        ]

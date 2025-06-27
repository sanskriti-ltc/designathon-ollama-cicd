import ollama
import json
import os
import re
import subprocess
import requests
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import git
from datetime import datetime

@dataclass
class FixResult:
    """Result of automatic bug fix attempt"""
    success: bool
    original_code: str
    fixed_code: str
    fix_description: str
    confidence: float

@dataclass
class PipelineResult:
    """CI/CD pipeline execution result"""
    stage: str
    success: bool
    message: str
    timestamp: datetime
    
@dataclass
class BugReport:
    """Data class for bug reports"""
    file_name: str
    file_path: str
    line_number: int
    bug_type: str
    severity: str
    description: str
    suggestion: str
    confidence: float

class EnhancedAICodeAgent:
    """Enhanced AI agent with bug fixing and CI/CD integration"""
    
    def __init__(self, model_name: str = "codellama", jira_config: Dict = None):
        self.model_name = model_name
        self.client = ollama.Client()
        self.jira_config = jira_config or {}
        self.pipeline_history = []
        # Java-specific bug patterns to focus the AI on
        self.bug_patterns = {
            "null_pointer": {
                "description": "Potential null pointer exceptions",
                "severity": "HIGH"
            },
            "resource_leak": {
                "description": "Resource not properly closed",
                "severity": "MEDIUM"
            },
            "exception_handling": {
                "description": "Poor exception handling",
                "severity": "MEDIUM"
            },
            "thread_safety": {
                "description": "Thread safety issues",
                "severity": "HIGH"
            },
            "performance": {
                "description": "Performance bottlenecks",
                "severity": "LOW"
            },
            "security": {
                "description": "Security vulnerabilities",
                "severity": "CRITICAL"
            }
        }
        
    def _analyze_file(self, file_path: str) -> List[BugReport]:
        """Analyze a Java file and return bug reports"""
        try:
            # Read the Java file
            with open(file_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
            
            # Pre-process code to add line numbers for reference
            numbered_lines = self._add_line_numbers(code_content)
            
            # Analyze code with AI
            bug_reports = self._ai_analyze_code(numbered_lines, Path(file_path).name, file_path)
            
            return bug_reports
            
        except Exception as e:
            print(f"Error analyzing file {file_path}: {str(e)}")
            return []
    
    def _add_line_numbers(self, code: str) -> str:
        """Add line numbers to code for better AI analysis"""
        lines = code.split('\n')
        numbered_lines = []
        for i, line in enumerate(lines, 1):
            numbered_lines.append(f"{i:3d}: {line}")
        return '\n'.join(numbered_lines)
    
    def _ai_analyze_code(self, numbered_code: str, file_name: str, file_path: str) -> List[BugReport]:
        """Use Ollama to analyze Java code for bugs"""
        
        # Craft the prompt for Java-specific analysis
        prompt = self._create_analysis_prompt(numbered_code)
        
        try:
            # Call Ollama
            response = self.client.chat(
                model=self.model_name,
                messages=[
                    {
                        'role': 'system',
                        'content': 'You are an expert Java code analyzer. Analyze code for bugs and return structured JSON responses.'
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                options={
                    'temperature': 0.1,  # Low temperature for consistent analysis
                    'top_p': 0.9,
                    'num_predict': 1000
                }
            )
            
            # Parse AI response
            ai_response = response['message']['content']
            bug_reports = self._parse_ai_response(ai_response, file_name, file_path)
            
            return bug_reports
            
        except Exception as e:
            print(f"Error in AI analysis: {str(e)}")
            return []
    
    def _create_analysis_prompt(self, numbered_code: str) -> str:
        """Create a structured prompt for Java code analysis"""
        
        bug_types = list(self.bug_patterns.keys())
        
        prompt = f"""
Analyze this Java code for potential bugs and issues. Focus on these categories:
{', '.join(bug_types)}

Java Code to analyze:
```java
{numbered_code}
```

For each bug found, provide a JSON object with this exact structure:
{{
    "line_number": <line number where issue occurs>,
    "bug_type": "<one of: {', '.join(bug_types)}>",
    "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
    "description": "<brief description of the issue>",
    "suggestion": "<how to fix this issue>",
    "confidence": <float between 0.0 and 1.0>
}}

Return your response as a JSON array of bug objects. If no bugs found, return an empty array [].

Example response format:
[
    {{
        "line_number": 15,
        "bug_type": "null_pointer",
        "severity": "HIGH",
        "description": "Variable 'user' might be null before calling getName()",
        "suggestion": "Add null check: if (user != null) {{ user.getName(); }}",
        "confidence": 0.85
    }}
]

Only return the JSON array, no other text.
"""
        return prompt
    
    def _parse_ai_response(self, ai_response: str, file_name: str, file_path: str) -> List[BugReport]:
        """Parse AI response and convert to BugReport objects"""
        bug_reports = []
        
        try:
            # Extract JSON from response (in case AI adds extra text)
            json_match = re.search(r'\[.*\]', ai_response, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                bugs_data = json.loads(json_str)
                
                for bug_data in bugs_data:
                    bug_report = BugReport(
                        file_name=file_name,
                        file_path=file_path,
                        line_number=bug_data.get('line_number', 0),
                        bug_type=bug_data.get('bug_type', 'unknown'),
                        severity=bug_data.get('severity', 'MEDIUM'),
                        description=bug_data.get('description', ''),
                        suggestion=bug_data.get('suggestion', ''),
                        confidence=bug_data.get('confidence', 0.5)
                    )
                    bug_reports.append(bug_report)
                    
        except json.JSONDecodeError as e:
            print(f"Failed to parse AI response as JSON: {str(e)}")
            print(f"AI Response: {ai_response}")
            
        return bug_reports
    
    def _generate_unit_tests(self, file_path: str, class_name: str = None) -> str:
        """Generate JUnit test cases for the Java file"""
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
            
            # Extract class name if not provided
            if not class_name:
                class_match = re.search(r'public class (\w+)', code_content)
                if class_match:
                    class_name = class_match.group(1)
                else:
                    class_name = "UnknownClass"
            
            test_prompt = f"""
Generate JUnit 5 test cases for this Java class. Create comprehensive tests including:
- Normal cases
- Edge cases 
- Error cases
- Null input handling

Java class to test:
```java
{code_content}
```

Generate a complete JUnit 5 test class named {class_name}Test with proper imports and annotations.
Include @Test, @BeforeEach, @AfterEach as needed.
Use assertions like assertEquals, assertThrows, assertNotNull, etc.

Return only the complete test class code, no explanations.
"""
            
            response = self.client.chat(
                model=self.model_name,
                messages=[
                    {
                        'role': 'system',
                        'content': 'You are a Java testing expert. Generate comprehensive JUnit 5 test cases.'
                    },
                    {
                        'role': 'user',
                        'content': test_prompt
                    }
                ],
                options={
                    'temperature': 0.2,
                    'num_predict': 1500
                }
            )
            
            return response['message']['content']
            
        except Exception as e:
            print(f"Error generating test cases: {str(e)}")
            return ""
        
    def analyze_and_fix_repository(self, repo_path: str) -> Dict[str, Any]:
        """Complete workflow: analyze → fix → test → deploy"""
        
        results = {
            "analysis_results": [],
            "fix_results": [],
            "test_results": [],
            "jira_tickets": [],
            "pipeline_status": "PENDING"
        }
        
        try:
            # Step 1: Discover and analyze Java files
            java_files = self._discover_java_files(repo_path)
            print(f"Found {len(java_files)} Java files to analyze")
            
            # Step 2: Analyze each file
            all_bugs = []
            for java_file in java_files:
                print(f"Analyzing {java_file}...")
                bugs = self._analyze_file(java_file)
                all_bugs.extend(bugs)
                results["analysis_results"].append({
                    "file": java_file,
                    "bugs_found": len(bugs),
                    "bugs": [self._bug_to_dict(bug) for bug in bugs]
                })
            
            print(f"Total bugs found: {len(all_bugs)}")
            
            # Step 3: Attempt automatic fixes for high-confidence bugs
            for bug in all_bugs:
                if bug.confidence > 0.8 and bug.severity in ['HIGH', 'CRITICAL']:
                    print(f"Attempting to fix: {bug.description}")
                    fix_result = self._attempt_bug_fix(bug)
                    results["fix_results"].append(fix_result)
            
            # Step 4: Generate comprehensive test suite
            test_code = self._generate_comprehensive_tests(repo_path, all_bugs)
            results["test_results"] = test_code
            
            # Step 5: Create JIRA tickets for remaining issues
            jira_tickets = self._create_jira_tickets(all_bugs)
            results["jira_tickets"] = jira_tickets
            
            # Step 6: Simulate CI/CD pipeline execution
            pipeline_status = self._simulate_ci_cd_pipeline(repo_path, results)
            results["pipeline_status"] = pipeline_status
            
            return results
            
        except Exception as e:
            print(f"Error in repository analysis: {str(e)}")
            results["pipeline_status"] = "FAILED"
            return results
    
    def _discover_java_files(self, repo_path: str) -> List[str]:
        """Find all Java files in repository"""
        java_files = []
        repo_path = Path(repo_path)
        
        # Look for Java files, excluding build directories
        for java_file in repo_path.rglob("*.java"):
            # Skip build/target directories
            if not any(skip in str(java_file) for skip in ['target', 'build', '.git']):
                java_files.append(str(java_file))
        
        return java_files
    
    def _attempt_bug_fix(self, bug) -> FixResult:
        """Attempt to automatically fix a bug"""
        
        try:
            # Read the original file
            with open(bug.file_path, 'r') as f:
                original_code = f.read()
            
            # Create fix prompt
            fix_prompt = f"""
Fix this Java bug automatically. Return ONLY the corrected code, no explanations.

Bug Details:
- Type: {bug.bug_type}
- Line: {bug.line_number}
- Issue: {bug.description}
- Suggested fix: {bug.suggestion}

Original Code:
```java
{original_code}
```

Return the complete fixed Java class with the bug resolved. Maintain all existing functionality.
"""
            
            response = self.client.chat(
                model=self.model_name,
                messages=[
                    {
                        'role': 'system',
                        'content': 'You are an expert Java developer. Fix bugs while preserving all functionality.'
                    },
                    {
                        'role': 'user',
                        'content': fix_prompt
                    }
                ],
                options={'temperature': 0.1, 'num_predict': 2000}
            )
            
            fixed_code = self._extract_code_from_response(response['message']['content'])
            
            # Validate the fix (basic syntax check)
            if self._validate_java_syntax(fixed_code):
                return FixResult(
                    success=True,
                    original_code=original_code,
                    fixed_code=fixed_code,
                    fix_description=f"Fixed {bug.bug_type} on line {bug.line_number}",
                    confidence=0.85
                )
            else:
                return FixResult(
                    success=False,
                    original_code=original_code,
                    fixed_code="",
                    fix_description="Fix failed syntax validation",
                    confidence=0.0
                )
                
        except Exception as e:
            return FixResult(
                success=False,
                original_code="",
                fixed_code="",
                fix_description=f"Fix attempt failed: {str(e)}",
                confidence=0.0
            )
    
    def _generate_comprehensive_tests(self, repo_path: str, bugs: List) -> Dict[str, str]:
        """Generate comprehensive test suite including bug-specific tests"""
        
        test_suite = {}
        
        # Generate unit tests for each class
        java_files = self._discover_java_files(repo_path)
        
        for java_file in java_files[:3]:  # Limit for demo
            try:
                with open(java_file, 'r') as f:
                    code_content = f.read()
                
                class_name = self._extract_class_name(code_content)
                if class_name:
                    # Generate regular unit tests
                    unit_tests = self._generate_unit_tests(java_file, class_name)
                    
                    # Generate bug-specific tests
                    bug_tests = self._generate_bug_tests(java_file, bugs)
                    
                    # Generate Cucumber scenarios
                    cucumber_scenarios = self._generate_cucumber_scenarios(java_file, bugs)
                    
                    test_suite[f"{class_name}Test.java"] = unit_tests
                    test_suite[f"{class_name}BugTests.java"] = bug_tests
                    test_suite[f"{class_name}.feature"] = cucumber_scenarios
                    
            except Exception as e:
                print(f"Error generating tests for {java_file}: {str(e)}")
        
        return test_suite
    
    def _generate_bug_tests(self, java_file: str, bugs: List) -> str:
        """Generate specific tests for detected bugs"""
        
        file_bugs = [bug for bug in bugs if bug.file_name in java_file]
        if not file_bugs:
            return ""
        
        test_prompt = f"""
Generate JUnit 5 tests specifically to verify bug fixes for these issues:

Bug Details:
{[f"- {bug.bug_type}: {bug.description}" for bug in file_bugs]}

Create tests that:
1. Test the problematic scenarios
2. Verify the bug doesn't occur
3. Test edge cases around the bug
4. Use @Test, assertThrows, assertNotNull, etc.

Return only the complete test class code.
"""
        
        try:
            response = self.client.chat(
                model=self.model_name,
                messages=[
                    {'role': 'system', 'content': 'Generate comprehensive bug-focused JUnit tests.'},
                    {'role': 'user', 'content': test_prompt}
                ],
                options={'temperature': 0.2, 'num_predict': 1500}
            )
            
            return response['message']['content']
            
        except Exception as e:
            return f"// Error generating bug tests: {str(e)}"
    
    def _generate_cucumber_scenarios(self, java_file: str, bugs: List) -> str:
        """Generate Cucumber BDD scenarios for bug testing"""
        
        file_bugs = [bug for bug in bugs if bug.file_name in java_file]
        if not file_bugs:
            return ""
        
        scenarios = ["Feature: Bug Prevention Tests\n"]
        
        for bug in file_bugs:
            scenario = f"""
  Scenario: Prevent {bug.bug_type} in {bug.file_name}
    Given the system is initialized
    When I trigger the scenario that caused the {bug.bug_type}
    Then the system should handle it gracefully
    And no {bug.bug_type} exception should occur
    And the system should remain stable
"""
            scenarios.append(scenario)
        
        return "\n".join(scenarios)
    
    def _create_jira_tickets(self, bugs: List) -> List[Dict]:
        """Create JIRA tickets for bugs (mock implementation)"""
        
        tickets = []
        
        # Group bugs by file and severity
        critical_bugs = [b for b in bugs if b.severity == 'CRITICAL']
        high_bugs = [b for b in bugs if b.severity == 'HIGH']
        
        # Create tickets for critical/high severity bugs
        for bug_group in [critical_bugs, high_bugs]:
            if bug_group:
                ticket = {
                    "summary": f"Code Quality Issues - {len(bug_group)} {bug_group[0].severity} priority bugs",
                    "description": self._create_jira_description(bug_group),
                    "issue_type": "Bug",
                    "priority": bug_group[0].severity,
                    "status": "CREATED",
                    "ticket_id": f"DEMO-{len(tickets) + 1}"
                }
                tickets.append(ticket)
        
        return tickets
    
    def _simulate_ci_cd_pipeline(self, repo_path: str, analysis_results: Dict) -> str:
        """Simulate CI/CD pipeline execution"""
        
        pipeline_stages = [
            "Code Checkout",
            "Dependency Installation", 
            "Code Compilation",
            "Unit Tests",
            "Integration Tests",
            "Code Quality Gate",
            "Security Scan",
            "Deploy to Staging",
            "Staging Tests",
            "Production Deployment"
        ]
        
        success_count = 0
        
        for stage in pipeline_stages:
            # Simulate stage execution
            success = self._simulate_pipeline_stage(stage, analysis_results)
            
            result = PipelineResult(
                stage=stage,
                success=success,
                message=f"{stage} {'PASSED' if success else 'FAILED'}",
                timestamp=datetime.now()
            )
            
            self.pipeline_history.append(result)
            
            if success:
                success_count += 1
                print(f"✅ {stage} - PASSED")
            else:
                print(f"❌ {stage} - FAILED")
                if stage in ["Code Compilation", "Unit Tests"]:
                    # Critical failures stop the pipeline
                    return "PIPELINE_FAILED"
        
        # Determine overall status
        if success_count == len(pipeline_stages):
            return "PIPELINE_SUCCESS"
        elif success_count >= len(pipeline_stages) * 0.8:
            return "PIPELINE_WARNING"
        else:
            return "PIPELINE_FAILED"
    
    def _simulate_pipeline_stage(self, stage: str, analysis_results: Dict) -> bool:
        """Simulate individual pipeline stage execution"""
        
        # Simulate different success rates based on code quality
        total_bugs = sum(len(result["bugs"]) for result in analysis_results["analysis_results"])
        critical_bugs = sum(1 for result in analysis_results["analysis_results"] 
                          for bug in result["bugs"] if bug["severity"] == "CRITICAL")
        
        # Higher bug count = higher failure probability
        if stage == "Code Quality Gate":
            return critical_bugs == 0  # Fail if critical bugs found
        elif stage in ["Unit Tests", "Integration Tests"]:
            return total_bugs < 5  # Fail if too many bugs
        else:
            return True  # Other stages pass for demo
    
    def generate_ci_cd_config(self) -> Dict[str, str]:
        """Generate CI/CD configuration files"""
        
        # GitHub Actions workflow
        github_actions = """
name: AI Code Quality Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  ai-code-analysis:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v3
      with:
        python-version: '3.9'
        
    - name: Install AI Code Agent
      run: |
        pip install ollama requests gitpython
        
    - name: Run AI Code Analysis
      run: |
        python ai_agent.py --analyze --repo-path . --output results.json
        
    - name: Generate Tests
      run: |
        python ai_agent.py --generate-tests --input results.json
        
    - name: Create JIRA Tickets
      run: |
        python ai_agent.py --create-tickets --input results.json
      env:
        JIRA_URL: ${{ secrets.JIRA_URL }}
        JIRA_TOKEN: ${{ secrets.JIRA_TOKEN }}
"""
        
        # Jenkins pipeline
        jenkins_pipeline = """
pipeline {
    agent any
    
    stages {
        stage('AI Code Analysis') {
            steps {
                script {
                    sh 'python ai_agent.py --analyze --repo-path . --output results.json'
                }
            }
        }
        
        stage('Auto Bug Fix') {
            steps {
                script {
                    sh 'python ai_agent.py --fix-bugs --input results.json'
                }
            }
        }
        
        stage('Generate Tests') {
            steps {
                script {
                    sh 'python ai_agent.py --generate-tests --input results.json'
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                script {
                    def results = readJSON file: 'results.json'
                    if (results.critical_bugs > 0) {
                        error("Critical bugs found - failing pipeline")
                    }
                }
            }
        }
    }
    
    post {
        always {
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'reports',
                reportFiles: 'ai-analysis-report.html',
                reportName: 'AI Code Analysis Report'
            ])
        }
    }
}
"""
        
        return {
            "github_actions": github_actions,
            "jenkins_pipeline": jenkins_pipeline
        }
    
    # Helper methods
    def _bug_to_dict(self, bug) -> Dict:
        """Convert BugReport to dictionary"""
        return {
            "file_name": bug.file_name,
            "file_path": bug.file_path,
            "line_number": bug.line_number,
            "bug_type": bug.bug_type,
            "severity": bug.severity,
            "description": bug.description,
            "suggestion": bug.suggestion,
            "confidence": bug.confidence
        }
    
    def _extract_code_from_response(self, response: str) -> str:
        """Extract Java code from AI response"""
        # Look for code blocks
        import re
        code_match = re.search(r'```java\n(.*?)\n```', response, re.DOTALL)
        if code_match:
            return code_match.group(1)
        return response.strip()
    
    def _validate_java_syntax(self, code: str) -> bool:
        """Basic Java syntax validation (simplified)"""
        # Basic checks - in real implementation, use proper Java parser
        return ('{' in code and '}' in code and 
                'class ' in code and 
                code.count('{') == code.count('}'))
    
    def _extract_class_name(self, code: str) -> str:
        """Extract class name from Java code"""
        import re
        match = re.search(r'public class (\w+)', code)
        return match.group(1) if match else "UnknownClass"
    
    def _create_jira_description(self, bugs: List) -> str:
        """Create JIRA ticket description"""
        description = f"*Automated Code Analysis - {len(bugs)} Issues Found*\n\n"
        
        for bug in bugs:
            description += f"* {bug.file_name}:{bug.line_number} - {bug.description}\n"
            description += f"  _Suggestion:_ {bug.suggestion}\n\n"
        
        return description

# Usage example for complete workflow
def main():
    """Demo the complete AI agent workflow"""
    
    # Initialize the enhanced agent
    agent = EnhancedAICodeAgent("codellama")
    
    # Run complete analysis workflow
    print("🚀 Starting AI Code Agent Pipeline...")
    results = agent.analyze_and_fix_repository("C:/Users/sansk/Documents/Github/demo-backend")
    
    # Display results
    print(f"\n📊 Analysis Complete:")
    print(f"Files analyzed: {len(results['analysis_results'])}")
    print(f"Bugs found: {sum(r['bugs_found'] for r in results['analysis_results'])}", "-"*50)
    # print the detailed bug reports
    for result in results['analysis_results']:
        print(f"File: {result['file']}, Bugs: {result['bugs_found']}")
        for bug in result['bugs']:
            print(f"  - {bug['bug_type']} (Line {bug['line_number']}): {bug['description']} (Confidence: {bug['confidence']})")
    print(f"Auto-fixes attempted: {len(results['fix_results'])}", "-"*50)
    print(f"\n🔧 Fix Results:")
    for fix in results['fix_results']:
        print(f"  - Success: {fix.success}, Description: {fix.fix_description}, Confidence: {fix.confidence}")
        print(f"    Original Code:\n{fix.original_code}")
        print(f"    Fixed Code:\n{fix.fixed_code}")
    print(f"JIRA tickets created: {len(results['jira_tickets'])}", "-"*50)
    print(f"\n📝 JIRA Tickets:")
    for ticket in results['jira_tickets']:
        print(f"  - {ticket['ticket_id']}: {ticket['summary']} (Priority: {ticket['priority']})")
    print(f"\n🔍 Test Suite Generated:", "-"*50)
    for test_file, test_code in results['test_results'].items():
        print(f"  - {test_file}:\n{test_code}")
    print(f"\n📈 CI/CD Pipeline Results:", "-"*50)
    for stage in agent.pipeline_history:
        print(f"  - {stage.stage}: {'PASSED' if stage.success else 'FAILED'} at {stage.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Pipeline status: {results['pipeline_status']}")

    
    # Generate CI/CD configs
    ci_cd_configs = agent.generate_ci_cd_config()
    print("\n🛠️ CI/CD Configurations:", "-"*50)
    print("GitHub Actions:\n", ci_cd_configs['github_actions'])
    print("\nJenkins Pipeline:\n", ci_cd_configs['jenkins_pipeline'])
    print(f"\n🔧 CI/CD configurations generated")

if __name__ == "__main__":
    main()

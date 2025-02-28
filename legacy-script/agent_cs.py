from langchain.agents import AgentExecutor, Tool
from langchain.tools.base import BaseTool
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_experimental.tools import PythonREPLTool
from langchain.graphs import Graph, StateGraph
from langchain.schema import Document
from langchain_community.llms import OpenAI
from langchain_openai import ChatOpenAI

from subprocess import Popen, PIPE, TimeoutExpired
import json
import time
import logging
import re
import ipaddress
from typing import Dict, List, Optional, Any, Union, Tuple
import os
from dotenv import load_dotenv

# Initialize Logging
logging.basicConfig(
    filename='security_pipeline.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class TargetScope:
    """Class to enforce and validate target scopes for security scanning."""
    
    def __init__(self, allowed_domains: List[str], allowed_ip_ranges: List[str]):
        self.allowed_domains = allowed_domains
        self.allowed_ip_ranges = [ipaddress.ip_network(ip_range) for ip_range in allowed_ip_ranges]
        
    def is_target_allowed(self, target: str) -> bool:
        """Check if the target is within the allowed scope."""
        # Check if it's an IP
        try:
            ip = ipaddress.ip_address(target)
            return any(ip in ip_range for ip_range in self.allowed_ip_ranges)
        except ValueError:
            # It's a domain
            return any(domain in target for domain in self.allowed_domains)

class SecurityTool(BaseTool):
    """Base tool for all security scanning operations."""
    
    name = "security_tool"
    description = "Generic security scanning tool"
    target_scope: TargetScope
    timeout_seconds: int = 300
    retry_attempts: int = 3
    
    def __init__(self, target_scope: TargetScope, **kwargs):
        super().__init__(**kwargs)
        self.target_scope = target_scope
    
    def execute_command(self, command: List[str], target: str) -> Tuple[str, bool]:
        """Execute a shell command with proper timeout and error handling."""
        if not self.target_scope.is_target_allowed(target):
            error_msg = f"Target {target} is outside the allowed scope. Operation aborted."
            logging.error(error_msg)
            return error_msg, False
        
        logging.info(f"Executing command: {' '.join(command)}")
        
        for attempt in range(self.retry_attempts):
            try:
                process = Popen(command, stdout=PIPE, stderr=PIPE)
                stdout, stderr = process.communicate(timeout=self.timeout_seconds)
                
                if process.returncode != 0:
                    error_msg = stderr.decode('utf-8', errors='replace')
                    logging.warning(f"Command failed (attempt {attempt+1}/{self.retry_attempts}): {error_msg}")
                    if attempt == self.retry_attempts - 1:
                        return f"Command failed after {self.retry_attempts} attempts: {error_msg}", False
                    time.sleep(2 * (attempt + 1))  # Exponential backoff
                    continue
                
                output = stdout.decode('utf-8', errors='replace')
                return output, True
                
            except TimeoutExpired:
                process.kill()
                logging.warning(f"Command timed out after {self.timeout_seconds}s (attempt {attempt+1}/{self.retry_attempts})")
                if attempt == self.retry_attempts - 1:
                    return f"Command timed out after {self.retry_attempts} attempts", False
                time.sleep(2 * (attempt + 1))  # Exponential backoff
                
            except Exception as e:
                logging.error(f"Error executing command: {e}")
                if attempt == self.retry_attempts - 1:
                    return f"Error executing command: {str(e)}", False
                time.sleep(2 * (attempt + 1))  # Exponential backoff
        
        return "All retry attempts failed", False

class NmapTool(SecurityTool):
    """Tool for running Nmap scans."""
    
    name = "nmap_scanner"
    description = "Run Nmap scan on a target to discover open ports and services"
    
    def _run(self, target: str, scan_type: str = "-sV") -> str:
        """Run an Nmap scan with the specified options."""
        command = ["nmap", scan_type, "-oN", f"nmap_{target.replace('/', '_')}.txt", target]
        output, success = self.execute_command(command, target)
        
        if not success:
            return f"Nmap scan failed: {output}"
        
        # Extract useful information
        open_ports = re.findall(r"(\d+/\w+)\s+open\s+(\w+)", output)
        services = {}
        for port_info, service in open_ports:
            port = port_info.split('/')[0]
            services[port] = service
        
        result = {
            "target": target,
            "open_ports": services,
            "raw_output": output
        }
        
        return json.dumps(result)

class GobusterTool(SecurityTool):
    """Tool for running directory discovery with Gobuster."""
    
    name = "gobuster_scanner"
    description = "Run Gobuster on a target to discover directories and files"
    
    def _run(self, target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
        """Run Gobuster directory scan."""
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
            
        command = ["gobuster", "dir", "-u", target, "-w", wordlist, "-o", f"gobuster_{target.replace('://', '_').replace('/', '_')}.txt"]
        output, success = self.execute_command(command, target)
        
        if not success:
            return f"Gobuster scan failed: {output}"
        
        # Extract directories
        directories = re.findall(r"/([\w\-\.]+)", output)
        
        result = {
            "target": target,
            "discovered_directories": directories,
            "raw_output": output
        }
        
        return json.dumps(result)

class FfufTool(SecurityTool):
    """Tool for fuzzing with ffuf."""
    
    name = "ffuf_scanner"
    description = "Run ffuf on a target URL to fuzz for endpoints"
    
    def _run(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
        """Run ffuf fuzzing."""
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
            
        command = ["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist, "-o", f"ffuf_{url.replace('://', '_').replace('/', '_')}.json", "-of", "json"]
        output, success = self.execute_command(command, url)
        
        if not success:
            return f"FFUF scan failed: {output}"
        
        # Try to read the JSON output file
        try:
            json_file = f"ffuf_{url.replace('://', '_').replace('/', '_')}.json"
            if os.path.exists(json_file):
                with open(json_file, 'r') as f:
                    ffuf_results = json.load(f)
                    
                    result = {
                        "target": url,
                        "discovered_endpoints": [item.get('input', {}).get('FUZZ') for item in ffuf_results.get('results', [])],
                        "status_codes": {item.get('input', {}).get('FUZZ'): item.get('status') for item in ffuf_results.get('results', [])}
                    }
                    
                    return json.dumps(result)
        except Exception as e:
            logging.error(f"Error processing ffuf results: {e}")
            
        # Fallback to parsing console output
        endpoints = re.findall(r"| (\w+)\s+\|\s+\d+", output)
        
        result = {
            "target": url,
            "discovered_endpoints": endpoints,
            "raw_output": output
        }
        
        return json.dumps(result)

class SqlmapTool(SecurityTool):
    """Tool for SQL injection testing with sqlmap."""
    
    name = "sqlmap_scanner"
    description = "Run sqlmap on a target URL to test for SQL injection vulnerabilities"
    
    def _run(self, url: str) -> str:
        """Run sqlmap scan."""
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
            
        command = ["sqlmap", "-u", url, "--batch", "--output-dir=sqlmap_results"]
        output, success = self.execute_command(command, url)
        
        if not success:
            return f"SQLMap scan failed: {output}"
        
        # Check for vulnerable keywords
        is_vulnerable = any(keyword in output for keyword in ["vulnerable", "parameter", "payload"])
        
        result = {
            "target": url,
            "is_vulnerable": is_vulnerable,
            "raw_output": output
        }
        
        return json.dumps(result)

class TaskPlanner:
    """Responsible for breaking down security tasks into executable steps."""
    
    def __init__(self, llm):
        self.llm = llm
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity expert tasked with breaking down security testing objectives into specific executable tasks.
            Focus on creating a logical, step-by-step approach that a security tool would follow.
            Return the tasks as a JSON list of objects with these fields:
            - task_type: The type of task (nmap_scan, gobuster_scan, ffuf_scan, sqlmap_scan)
            - target: The target to scan
            - description: A brief description of what this task aims to accomplish
            - priority: A number from 1-5 with 1 being highest priority
            """),
            ("human", "{objective}\n\nTarget scope: {allowed_targets}")
        ])
        
    def plan_tasks(self, objective: str, allowed_targets: List[str]) -> List[Dict]:
        """Break down a security objective into planned tasks."""
        response = self.llm.invoke(
            self.prompt.format(
                objective=objective,
                allowed_targets=", ".join(allowed_targets)
            )
        )
        
        # Extract JSON from the response
        task_list_str = re.search(r'```json\n(.*?)\n```', response.content, re.DOTALL)
        if task_list_str:
            task_list = json.loads(task_list_str.group(1))
        else:
            # Try to find JSON without code block
            task_list_str = re.search(r'\[\s*\{.*\}\s*\]', response.content, re.DOTALL)
            if task_list_str:
                task_list = json.loads(task_list_str.group(0))
            else:
                logging.error(f"Could not parse task list from: {response.content}")
                task_list = []
        
        return task_list

class ResultAnalyzer:
    """Analyzes scan results and recommends follow-up tasks."""
    
    def __init__(self, llm):
        self.llm = llm
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity expert analyzing the results of a security scan. 
            Based on these results, recommend follow-up tasks to further investigate any findings.
            Return your recommendations as a JSON list of objects with these fields:
            - task_type: The type of task (nmap_scan, gobuster_scan, ffuf_scan, sqlmap_scan)
            - target: The specific target to scan (could be a URL, domain, IP, etc.)
            - description: A brief description of why this follow-up task is needed
            - priority: A number from 1-5 with 1 being highest priority
            Focus only on the most promising leads. Quality over quantity.
            """),
            ("human", "Scan Type: {scan_type}\nTarget: {target}\nResults: {results}")
        ])
        
    def analyze_results(self, scan_type: str, target: str, results: str) -> List[Dict]:
        """Analyze scan results and recommend follow-up tasks."""
        response = self.llm.invoke(
            self.prompt.format(
                scan_type=scan_type,
                target=target,
                results=results
            )
        )
        
        # Extract JSON from the response
        tasks_str = re.search(r'```json\n(.*?)\n```', response.content, re.DOTALL)
        if tasks_str:
            follow_up_tasks = json.loads(tasks_str.group(1))
        else:
            # Try to find JSON without code block
            tasks_str = re.search(r'\[\s*\{.*\}\s*\]', response.content, re.DOTALL)
            if tasks_str:
                follow_up_tasks = json.loads(tasks_str.group(0))
            else:
                logging.error(f"Could not parse follow-up tasks from: {response.content}")
                follow_up_tasks = []
        
        return follow_up_tasks

class SecurityAuditAgent:
    """Main agent class that coordinates the security audit workflow."""
    
    def __init__(self, allowed_domains: List[str], allowed_ip_ranges: List[str], api_key: str = None):
        # Initialize LLM
        self.llm = ChatOpenAI(temperature=0, api_key=api_key, model="gpt-4")
        
        # Set up scope
        self.target_scope = TargetScope(allowed_domains, allowed_ip_ranges)
        
        # Initialize components
        self.task_planner = TaskPlanner(self.llm)
        self.result_analyzer = ResultAnalyzer(self.llm)
        
        # Set up tools
        self.nmap_tool = NmapTool(target_scope=self.target_scope)
        self.gobuster_tool = GobusterTool(target_scope=self.target_scope)
        self.ffuf_tool = FfufTool(target_scope=self.target_scope)
        self.sqlmap_tool = SqlmapTool(target_scope=self.target_scope)
        
        # Task queue and results
        self.task_queue = []
        self.completed_tasks = []
        self.results = {}
        self.running = False
        
    def initialize_workflow(self, objective: str):
        """Initialize the security audit workflow with an objective."""
        logging.info(f"Initializing security audit workflow with objective: {objective}")
        
        # Plan initial tasks
        initial_tasks = self.task_planner.plan_tasks(
            objective, 
            self.target_scope.allowed_domains + [str(ip) for ip in self.target_scope.allowed_ip_ranges]
        )
        
        # Add tasks to queue
        for task in initial_tasks:
            self.add_task(task)
            
        logging.info(f"Initial task plan created with {len(self.task_queue)} tasks")
        return initial_tasks
    
    def add_task(self, task: Dict):
        """Add a task to the queue."""
        # Validate task is in scope
        if not self.target_scope.is_target_allowed(task['target']):
            logging.warning(f"Task for target {task['target']} rejected as out of scope")
            return False
        
        # Check if this exact task is already in the queue or completed
        task_signature = f"{task['task_type']}:{task['target']}"
        if task_signature in [f"{t['task_type']}:{t['target']}" for t in self.task_queue + self.completed_tasks]:
            logging.info(f"Task {task_signature} already exists, skipping")
            return False
        
        # Add to queue
        self.task_queue.append(task)
        logging.info(f"Added task to queue: {task['task_type']} on {task['target']}")
        
        # Sort queue by priority
        self.task_queue.sort(key=lambda x: x.get('priority', 3))
        return True
    
    def run_task(self, task: Dict) -> Dict:
        """Execute a specific task and return results."""
        task_type = task['task_type']
        target = task['target']
        
        start_time = time.time()
        logging.info(f"Starting task: {task_type} on {target}")
        
        result = None
        success = False
        
        try:
            if task_type == 'nmap_scan':
                result = self.nmap_tool._run(target)
                success = "failed" not in result.lower()
                
            elif task_type == 'gobuster_scan':
                result = self.gobuster_tool._run(target)
                success = "failed" not in result.lower()
                
            elif task_type == 'ffuf_scan':
                result = self.ffuf_tool._run(target)
                success = "failed" not in result.lower()
                
            elif task_type == 'sqlmap_scan':
                result = self.sqlmap_tool._run(target)
                success = "failed" not in result.lower()
                
            else:
                logging.warning(f"Unknown task type: {task_type}")
                result = json.dumps({"error": f"Unknown task type: {task_type}"})
                success = False
                
        except Exception as e:
            logging.error(f"Error executing {task_type} on {target}: {str(e)}")
            result = json.dumps({"error": str(e)})
            success = False
        
        execution_time = time.time() - start_time
        logging.info(f"Task completed in {execution_time:.2f}s: {task_type} on {target}, success: {success}")
        
        # Record result
        task_result = {
            "task": task,
            "result": result,
            "success": success,
            "execution_time": execution_time,
            "timestamp": time.time()
        }
        
        return task_result
    
    def analyze_and_update(self, task_result: Dict):
        """Analyze task results and create follow-up tasks."""
        if not task_result['success']:
            logging.warning(f"Task failed, skipping analysis: {task_result['task']['task_type']} on {task_result['task']['target']}")
            return
        
        # Add to completed tasks
        self.completed_tasks.append(task_result['task'])
        
        # Store result
        task_signature = f"{task_result['task']['task_type']}:{task_result['task']['target']}"
        self.results[task_signature] = task_result
        
        # Analyze results for follow-up tasks
        follow_up_tasks = self.result_analyzer.analyze_results(
            task_result['task']['task_type'],
            task_result['task']['target'],
            task_result['result']
        )
        
        # Add follow-up tasks to queue
        for task in follow_up_tasks:
            self.add_task(task)
            
        logging.info(f"Added {len(follow_up_tasks)} follow-up tasks based on results analysis")
    
    def run_workflow(self):
        """Run the security audit workflow until completion or interrupted."""
        if self.running:
            logging.warning("Workflow is already running")
            return
        
        self.running = True
        logging.info(f"Starting security audit workflow with {len(self.task_queue)} tasks in queue")
        
        try:
            while self.task_queue and self.running:
                # Get next task
                current_task = self.task_queue.pop(0)
                
                # Execute task
                task_result = self.run_task(current_task)
                
                # Analyze results and update task queue
                self.analyze_and_update(task_result)
                
                # Brief pause to avoid overwhelming system resources
                time.sleep(1)
                
            logging.info(f"Workflow completed with {len(self.completed_tasks)} tasks executed")
            return self.generate_report()
            
        except KeyboardInterrupt:
            logging.info("Workflow interrupted by user")
            self.running = False
            return self.generate_report()
            
        except Exception as e:
            logging.error(f"Error in workflow execution: {str(e)}")
            self.running = False
            return self.generate_report()
    
    def generate_report(self) -> str:
        """Generate a comprehensive security report based on all findings."""
        report_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity expert generating a comprehensive security report.
            Summarize the findings from the security audit in a clear, professional manner.
            Highlight critical vulnerabilities first, followed by moderate and low-risk issues.
            For each finding, include:
            1. A clear description of the vulnerability or issue
            2. The affected target(s)
            3. Potential impact
            4. Recommended remediation steps
            
            Format your report in Markdown with appropriate sections and organization.
            """),
            ("human", "Here are the results of all security scans conducted:\n{results}")
        ])
        
        # Prepare results for the report
        results_summary = []
        for task_signature, result in self.results.items():
            results_summary.append(f"Task: {task_signature}\nSuccess: {result['success']}\nResult: {result['result']}\n")
        
        report = self.llm.invoke(
            report_prompt.format(results="\n---\n".join(results_summary))
        )
        
        # Save report to file
        report_path = f"security_report_{time.strftime('%Y%m%d_%H%M%S')}.md"
        with open(report_path, 'w') as f:
            f.write(report.content)
        
        logging.info(f"Security report generated and saved to {report_path}")
        return report.content

# Example usage
if __name__ == "__main__":
    # Define the allowed scope
    allowed_domains = ["example.com", "test.example.com"]
    allowed_ip_ranges = ["192.168.1.0/24", "10.0.0.0/16"]
    
    # Replace with your API key
    # Load environment variables from .env file
    load_dotenv()
    api_key = os.environ.get("OPENAI_API_KEY", "")
    
    # Initialize the agent
    agent = SecurityAuditAgent(allowed_domains, allowed_ip_ranges, api_key)
    
    # Set the security objective
    objective = """Perform a comprehensive security assessment of example.com. 
    Identify open ports, discover hidden directories, and test for common web vulnerabilities 
    including SQL injection. Ensure all tests are non-intrusive and respect the target scope."""
    
    # Initialize and run the workflow
    agent.initialize_workflow(objective)
    report = agent.run_workflow()
    
    print("Security audit completed. Report saved.")
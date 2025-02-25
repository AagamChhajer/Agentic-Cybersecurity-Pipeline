import os
import json
import time
import logging
import re
import ipaddress
from typing import TypedDict, List, Dict, Any, Tuple, Optional
from subprocess import Popen, PIPE, TimeoutExpired
from dotenv import load_dotenv

# LangGraph and LangChain imports
from langgraph.graph import START, END, StateGraph
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI

print("Before Logging")
# Initialize Logging
logging.basicConfig(
    filename='security_pipeline.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# State management
class SecurityAuditState(TypedDict):
    objective: str  # Security objective set by the user
    target_scope: Dict  # Allowed domains and IP ranges
    task_queue: List  # List of pending tasks
    completed_tasks: List  # List of completed tasks
    results: Dict  # Results of completed tasks
    report: str  # Final security report


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
    
    def to_dict(self) -> Dict:
        """Convert the scope to a dictionary for state storage."""
        return {
            "allowed_domains": self.allowed_domains,
            "allowed_ip_ranges": [str(ip_range) for ip_range in self.allowed_ip_ranges]
        }
    
    @classmethod
    def from_dict(cls, scope_dict: Dict) -> 'TargetScope':
        """Create a TargetScope instance from a dictionary."""
        return cls(
            allowed_domains=scope_dict["allowed_domains"],
            allowed_ip_ranges=scope_dict["allowed_ip_ranges"]
        )


class SecurityScanner:
    """Base class for all security scanning operations."""
    
    def __init__(self, timeout_seconds: int = 300, retry_attempts: int = 3):
        self.timeout_seconds = timeout_seconds
        self.retry_attempts = retry_attempts
    
    def execute_command(self, command: List[str], target: str, target_scope: TargetScope) -> Tuple[str, bool]:
        """Execute a shell command with proper timeout and error handling."""
        if not target_scope.is_target_allowed(target):
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


class NmapScanner(SecurityScanner):
    """Tool for running Nmap scans."""
    
    def scan(self, target: str, target_scope: TargetScope, scan_type: str = "-sV") -> Dict:
        """Run an Nmap scan with the specified options."""
        command = ["nmap", scan_type, "-oN", f"nmap_{target.replace('/', '_')}.txt", target]
        output, success = self.execute_command(command, target, target_scope)
        
        if not success:
            return {"error": f"Nmap scan failed: {output}"}
        
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
        
        return result


class GobusterScanner(SecurityScanner):
    """Tool for running directory discovery with Gobuster."""
    
    def scan(self, target: str, target_scope: TargetScope, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> Dict:
        """Run Gobuster directory scan."""
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
            
        command = ["gobuster", "dir", "-u", target, "-w", wordlist, "-o", f"gobuster_{target.replace('://', '_').replace('/', '_')}.txt"]
        output, success = self.execute_command(command, target, target_scope)
        
        if not success:
            return {"error": f"Gobuster scan failed: {output}"}
        
        # Extract directories
        directories = re.findall(r"/([\w\-\.]+)", output)
        
        result = {
            "target": target,
            "discovered_directories": directories,
            "raw_output": output
        }
        
        return result


class FfufScanner(SecurityScanner):
    """Tool for fuzzing with ffuf."""
    
    def scan(self, target: str, target_scope: TargetScope, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> Dict:
        """Run ffuf fuzzing."""
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
            
        command = ["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist, "-o", f"ffuf_{target.replace('://', '_').replace('/', '_')}.json", "-of", "json"]
        output, success = self.execute_command(command, target, target_scope)
        
        if not success:
            return {"error": f"FFUF scan failed: {output}"}
        
        # Try to read the JSON output file
        try:
            json_file = f"ffuf_{target.replace('://', '_').replace('/', '_')}.json"
            if os.path.exists(json_file):
                with open(json_file, 'r') as f:
                    ffuf_results = json.load(f)
                    
                    result = {
                        "target": target,
                        "discovered_endpoints": [item.get('input', {}).get('FUZZ') for item in ffuf_results.get('results', [])],
                        "status_codes": {item.get('input', {}).get('FUZZ'): item.get('status') for item in ffuf_results.get('results', [])}
                    }
                    
                    return result
        except Exception as e:
            logging.error(f"Error processing ffuf results: {e}")
            
        # Fallback to parsing console output
        endpoints = re.findall(r"| (\w+)\s+\|\s+\d+", output)
        
        result = {
            "target": target,
            "discovered_endpoints": endpoints,
            "raw_output": output
        }
        
        return result


class SqlmapScanner(SecurityScanner):
    """Tool for SQL injection testing with sqlmap."""
    
    def scan(self, target: str, target_scope: TargetScope) -> Dict:
        """Run sqlmap scan."""
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
            
        command = ["sqlmap", "-u", target, "--batch", "--output-dir=sqlmap_results"]
        output, success = self.execute_command(command, target, target_scope)
        
        if not success:
            return {"error": f"SQLMap scan failed: {output}"}
        
        # Check for vulnerable keywords
        is_vulnerable = any(keyword in output for keyword in ["vulnerable", "parameter", "payload"])
        
        result = {
            "target": target,
            "is_vulnerable": is_vulnerable,
            "raw_output": output
        }
        
        return result


# LangGraph Node Functions
def initialize_audit(state: SecurityAuditState) -> SecurityAuditState:
    """Initialize the security audit with objective and scope."""
    logging.info(f"Initializing security audit with objective: {state['objective']}")
    
    # Create or restore target scope
    if isinstance(state['target_scope'], dict):
        target_scope = TargetScope.from_dict(state['target_scope'])
    else:
        # Default scope if none provided
        target_scope = TargetScope(["example.com"], ["192.168.1.0/24"])
        state['target_scope'] = target_scope.to_dict()
    
    # Set up LLM
    load_dotenv()
    api_key = os.environ.get("OPENAI_API_KEY", "")
    llm = ChatOpenAI(temperature=0, model="gpt-4", api_key=api_key)
    
    # Create initial task plan
    prompt = ChatPromptTemplate.from_messages([
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
    
    response = llm.invoke(
        prompt.format(
            objective=state['objective'],
            allowed_targets=", ".join(target_scope.allowed_domains + [str(ip) for ip in target_scope.allowed_ip_ranges])
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
    
    # Sort tasks by priority
    task_list.sort(key=lambda x: x.get('priority', 3))
    
    # Update state
    state['task_queue'] = task_list
    state['completed_tasks'] = []
    state['results'] = {}
    
    logging.info(f"Initial task plan created with {len(state['task_queue'])} tasks")
    return state


def execute_next_task(state: SecurityAuditState) -> SecurityAuditState:
    """Execute the next task in the queue."""
    if not state['task_queue']:
        logging.info("No tasks remaining in queue")
        return state
    
    # Get the next task
    task = state['task_queue'].pop(0)
    logging.info(f"Executing task: {task['task_type']} on {task['target']}")
    
    # Create target scope
    target_scope = TargetScope.from_dict(state['target_scope'])
    
    # Execute the task
    result = None
    success = False
    start_time = time.time()
    
    try:
        if task['task_type'] == 'nmap_scan':
            scanner = NmapScanner()
            result = scanner.scan(task['target'], target_scope)
            success = "error" not in result
            
        elif task['task_type'] == 'gobuster_scan':
            scanner = GobusterScanner()
            result = scanner.scan(task['target'], target_scope)
            success = "error" not in result
            
        elif task['task_type'] == 'ffuf_scan':
            scanner = FfufScanner()
            result = scanner.scan(task['target'], target_scope)
            success = "error" not in result
            
        elif task['task_type'] == 'sqlmap_scan':
            scanner = SqlmapScanner()
            result = scanner.scan(task['target'], target_scope)
            success = "error" not in result
            
        else:
            logging.warning(f"Unknown task type: {task['task_type']}")
            result = {"error": f"Unknown task type: {task['task_type']}"}
            success = False
            
    except Exception as e:
        logging.error(f"Error executing {task['task_type']} on {task['target']}: {str(e)}")
        result = {"error": str(e)}
        success = False
    
    execution_time = time.time() - start_time
    logging.info(f"Task completed in {execution_time:.2f}s: {task['task_type']} on {task['target']}, success: {success}")
    
    # Record result
    task_result = {
        "task": task,
        "result": result,
        "success": success,
        "execution_time": execution_time,
        "timestamp": time.time()
    }
    
    # Add to completed tasks
    state['completed_tasks'].append(task)
    
    # Store result
    task_signature = f"{task['task_type']}:{task['target']}"
    state['results'][task_signature] = task_result
    
    return state


def analyze_results(state: SecurityAuditState) -> SecurityAuditState:
    """Analyze the results of completed tasks and generate follow-up tasks."""
    if not state['completed_tasks']:
        return state
    
    # Get the most recently completed task
    last_task = state['completed_tasks'][-1]
    task_signature = f"{last_task['task_type']}:{last_task['target']}"
    task_result = state['results'].get(task_signature)
    
    if not task_result or not task_result['success']:
        # Skip analysis for failed tasks
        return state
    
    # Set up LLM
    llm = ChatOpenAI(temperature=0, model="gpt-4")
    
    # Create follow-up tasks
    prompt = ChatPromptTemplate.from_messages([
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
    
    response = llm.invoke(
        prompt.format(
            scan_type=last_task['task_type'],
            target=last_task['target'],
            results=json.dumps(task_result['result'])
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
    
    # Create target scope
    target_scope = TargetScope.from_dict(state['target_scope'])
    
    # Filter and add follow-up tasks
    filtered_tasks = []
    for task in follow_up_tasks:
        # Skip if already in the queue or completed
        task_signature = f"{task['task_type']}:{task['target']}"
        if task_signature in [f"{t['task_type']}:{t['target']}" for t in state['task_queue'] + state['completed_tasks']]:
            logging.info(f"Task {task_signature} already exists, skipping")
            continue
        
        # Skip if out of scope
        if not target_scope.is_target_allowed(task['target']):
            logging.warning(f"Task for target {task['target']} rejected as out of scope")
            continue
        
        filtered_tasks.append(task)
    
    # Sort by priority and add to queue
    filtered_tasks.sort(key=lambda x: x.get('priority', 3))
    state['task_queue'].extend(filtered_tasks)
    
    logging.info(f"Added {len(filtered_tasks)} follow-up tasks based on results analysis")
    return state


def should_continue(state: SecurityAuditState) -> str:
    """Determine whether to continue executing tasks or finalize the audit."""
    if state['task_queue']:
        return "execute_task"
    else:
        return "generate_report"


def generate_report(state: SecurityAuditState) -> SecurityAuditState:
    """Generate a comprehensive security report based on all findings."""
    logging.info("Generating security report")
    
    # Set up LLM
    llm = ChatOpenAI(temperature=0, model="gpt-4")
    
    # Create report
    prompt = ChatPromptTemplate.from_messages([
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
        ("human", "Security Audit Objective: {objective}\n\nHere are the results of all security scans conducted:\n{results}")
    ])
    
    # Prepare results for the report
    results_summary = []
    for task_signature, result in state['results'].items():
        if result['success']:
            results_summary.append(f"Task: {task_signature}\nSuccess: {result['success']}\nResult: {json.dumps(result['result'])}\n")
    
    response = llm.invoke(
        prompt.format(
            objective=state['objective'],
            results="\n---\n".join(results_summary)
        )
    )
    
    # Save report to file
    report_path = f"security_report_{time.strftime('%Y%m%d_%H%M%S')}.md"
    with open(report_path, 'w') as f:
        f.write(response.content)
    
    # Update state
    state['report'] = response.content
    
    logging.info(f"Security report generated and saved to {report_path}")
    return state


# Graph workflow building
def build_security_audit_workflow():
    """Build and return the security audit workflow graph."""
    # Initialize the StateGraph
    workflow = StateGraph(SecurityAuditState)
    
    # Add nodes to the graph
    workflow.add_node("initialize_audit", initialize_audit)
    workflow.add_node("execute_task", execute_next_task)
    workflow.add_node("analyze_results", analyze_results)
    workflow.add_node("generate_report", generate_report)
    
    # Add edges
    workflow.add_edge(START, "initialize_audit")
    workflow.add_edge("initialize_audit", "execute_task")
    workflow.add_edge("execute_task", "analyze_results")
    workflow.add_conditional_edges(
        "analyze_results",
        should_continue,
        {
            "execute_task": "execute_task",
            "generate_report": "generate_report"
        }
    )
    workflow.add_edge("generate_report", END)
    
    # Compile the graph
    return workflow.compile()


# Main function to run the security audit
def run_security_audit(objective: str, allowed_domains: List[str], allowed_ip_ranges: List[str]) -> str:
    """Run a security audit with the given objective and scope."""
    # Create target scope
    target_scope = TargetScope(allowed_domains, allowed_ip_ranges)
    
    # Initialize state
    init_state = SecurityAuditState(
        objective=objective,
        target_scope=target_scope.to_dict(),
        task_queue=[],
        completed_tasks=[],
        results={},
        report=""
    )
    
    # Build and run workflow
    workflow = build_security_audit_workflow()
    final_state = workflow.invoke(init_state)
    
    return final_state['report']


# Example usage
if __name__ == "__main__":
    # Define the allowed scope
    print("Hello")
    allowed_domains = ["google.com", "youtube.com"]
    allowed_ip_ranges = ["192.168.1.0/24", "10.0.0.0/16"]
    
    # Set the security objective
    objective = """Perform a comprehensive security assessment of google.com. 
    Identify open ports, discover hidden directories, and test for common web vulnerabilities 
    including SQL injection. Ensure all tests are non-intrusive and respect the target scope."""
    
    # Run the security audit
    report = run_security_audit(objective, allowed_domains, allowed_ip_ranges)
    
    print("Security audit completed. Report generated.")
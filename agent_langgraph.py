import os
import json
import time
import logging
import re
import ipaddress
import sys
from typing import TypedDict, List, Dict, Any, Tuple, Optional, Annotated
from subprocess import Popen, PIPE, TimeoutExpired
from dotenv import load_dotenv

# LangGraph and LangChain imports
from langgraph.graph import START, END, StateGraph
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI
from langgraph.managed.is_last_step import RemainingSteps

# Initialize Logging with both file and stream handlers
logger = logging.getLogger('SecurityAudit')
logger.setLevel(logging.INFO)

# Create formatters and handlers
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# File handler
file_handler = logging.FileHandler('security_pipeline.log')
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)

# Stream handler for terminal output
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(formatter)
stream_handler.setLevel(logging.INFO) 

# Add both handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# Ensure we don't get duplicate logs
logger.propagate = False

# Log initial message to verify setup
logger.info("Security Audit Pipeline Initialized")

# State management
class SecurityAuditState(TypedDict):
    objective: str  # Security objective set by the user
    target_scope: Dict  # Allowed domains and IP ranges
    task_queue: List  # List of pending tasks
    completed_tasks: List  # List of completed tasks
    results: Dict  # Results of completed tasks
    report: str  # Final security report
    task_complete: bool  # Added stop condition flag
    remaining_steps: RemainingSteps  # Track remaining steps
    seen_tasks: Dict[str, bool]  # Track unique tasks that have been processed


class TargetScope:
    """Class to enforce and validate target scopes for security scanning."""
    
    def __init__(self, allowed_domains: List[str], allowed_ip_ranges: List[str]):
        # Normalize domains (remove http/https and www)
        self.allowed_domains = [self._normalize_domain(domain) for domain in allowed_domains]
        self.allowed_ip_ranges = [ipaddress.ip_network(ip_range) for ip_range in allowed_ip_ranges]
        # logger.info(f"Initialized target scope with domains: {self.allowed_domains}")
        # logger.info(f"Initialized target scope with IP ranges: {self.allowed_ip_ranges}")
    
    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain by removing protocol and www."""
        domain = domain.lower()
        domain = re.sub(r'^https?://', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        return domain.strip('/')
    
    def is_target_allowed(self, target: str) -> bool:
        """Check if the target is within the allowed scope."""
        # Normalize the target
        target = self._normalize_domain(target)
        
        # Check if it's an IP
        try:
            ip = ipaddress.ip_address(target)
            is_allowed = any(ip in ip_range for ip_range in self.allowed_ip_ranges)
            if not is_allowed:
                logger.warning(f"IP {target} is outside allowed scope {self.allowed_ip_ranges}")
            return is_allowed
        except ValueError:
            # It's a domain
            is_allowed = any(
                target == allowed_domain or  # Exact match
                target.endswith('.' + allowed_domain)  # Subdomain
                for allowed_domain in self.allowed_domains
            )
            if not is_allowed:
                logger.warning(f"Domain {target} is outside allowed scope {self.allowed_domains}")
            return is_allowed
    
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
        # Normalize and validate target
        normalized_target = target_scope._normalize_domain(target)
        if not target_scope.is_target_allowed(normalized_target):
            error_msg = f"Target {target} is outside the allowed scope {target_scope.allowed_domains}. Operation terminated."
            logger.error(error_msg)
            return error_msg, False
        
        logger.info(f"Executing command for validated target {normalized_target}: {' '.join(command)}")
        
        for attempt in range(self.retry_attempts):
            try:
                process = Popen(command, stdout=PIPE, stderr=PIPE)
                stdout, stderr = process.communicate(timeout=self.timeout_seconds)
                
                if process.returncode != 0:
                    error_msg = stderr.decode('utf-8', errors='replace')
                    logger.warning(f"Command failed (attempt {attempt+1}/{self.retry_attempts}): {error_msg}")
                    if attempt == self.retry_attempts - 1:
                        return f"Command failed after {self.retry_attempts} attempts: {error_msg}", False
                    time.sleep(2 * (attempt + 1))  # Exponential backoff
                    continue
                
                output = stdout.decode('utf-8', errors='replace')
                return output, True
                
            except TimeoutExpired:
                process.kill()
                logger.warning(f"Command timed out after {self.timeout_seconds}s (attempt {attempt+1}/{self.retry_attempts})")
                if attempt == self.retry_attempts - 1:
                    return f"Command timed out after {self.retry_attempts} attempts", False
                time.sleep(2 * (attempt + 1))  # Exponential backoff
                
            except Exception as e:
                logger.error(f"Error executing command: {e}")
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
    
    def scan(self, target: str, target_scope: TargetScope, wordlist: str = "/Users/aagamchhajer/wordlists/SecLists/Discovery/Web-Content/common.txt") -> Dict:
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
    
    def scan(self, target: str, target_scope: TargetScope, wordlist: str = "/Users/aagamchhajer/wordlists/SecLists/Discovery/Web-Content/common.txt") -> Dict:
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
            logger.error(f"Error processing ffuf results: {e}")
            
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
    logger.info(f"Initializing security audit with objective: {state['objective']}")
    
    # Initialize state tracking
    state['remaining_steps'] = 50
    state['seen_tasks'] = {}
    
    # Create or restore target scope with strict validation
    if isinstance(state['target_scope'], dict):
        target_scope = TargetScope.from_dict(state['target_scope'])
    else:
        logger.error("No target scope provided. Audit cannot proceed.")
        state['task_complete'] = True
        state['report'] = "Error: No target scope provided. Audit terminated."
        return state
    
    # Validate all domains before proceeding
    invalid_domains = []
    for domain in target_scope.allowed_domains:
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-_.]*[a-zA-Z0-9]$', domain):
            invalid_domains.append(domain)
    
    if invalid_domains:
        logger.error(f"Invalid domains found in scope: {invalid_domains}")
        state['task_complete'] = True
        state['report'] = f"Error: Invalid domains in scope: {invalid_domains}. Audit terminated."
        return state
    

    # Set up LLM
    load_dotenv()
    api_key = os.environ.get("OPENAI_API_KEY", "")
    llm = ChatOpenAI(temperature=0, model="gpt-4o-mini", api_key=api_key)
    
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
    allowed_targets=", ".join(target_scope.allowed_domains + [str(ip) for ip in target_scope.allowed_ip_ranges])
    response = llm.invoke(
        prompt.format(
            objective=state['objective'],
            allowed_targets=allowed_targets)
        )
    
    print("Allowed Targets : ",allowed_targets)
    
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
            logger.error(f"Could not parse task list from: {response.content}")
            task_list = []
    
    # Sort tasks by priority
    task_list.sort(key=lambda x: x.get('priority', 3))
    tasks_log_dir = 'tasks_logs'
    os.makedirs(tasks_log_dir, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    tasks_log_path = os.path.join(tasks_log_dir, f"initial_tasks_{timestamp}.json")
    
    with open(tasks_log_path, 'w') as f:
        json.dump({
            "timestamp": timestamp,
            "objective": state['objective'],
            "target_scope": state['target_scope'],
            "tasks": task_list
        }, f, indent=2)
    
    # Update state
    state['task_queue'] = task_list
    state['completed_tasks'] = []
    state['results'] = {}
    
    logger.info(f"Initial task plan created with {len(state['task_queue'])} tasks")
    return state


def execute_next_task(state: SecurityAuditState) -> SecurityAuditState:
    """Execute the next task in the queue."""
    if not state['task_queue']:
        logger.info("No tasks remaining in queue")
        return state
    
    # Get the next task
    task = state['task_queue'].pop(0)
    task_target = task['target']
    
    # Create target scope
    target_scope = TargetScope.from_dict(state['target_scope'])
    
    # Normalize the target
    normalized_target = target_scope._normalize_domain(task_target)
    task_signature = f"{task['task_type']}:{normalized_target}"
    
    # Check if task has already been executed
    if task_signature in state['seen_tasks']:
        logger.info(f"Task {task_signature} already executed, skipping")
        return state
    
    logger.info(f"Executing task: {task_signature}")
    
    # Execute the task
    result = None
    success = False
    start_time = time.time()
    
    try:
        if task['task_type'] == 'nmap_scan':
            scanner = NmapScanner()
            result = scanner.scan(normalized_target, target_scope)
            success = "error" not in result
            
        elif task['task_type'] == 'gobuster_scan':
            scanner = GobusterScanner()
            result = scanner.scan(normalized_target, target_scope)
            success = "error" not in result
            
        elif task['task_type'] == 'ffuf_scan':
            scanner = FfufScanner()
            result = scanner.scan(normalized_target, target_scope)
            success = "error" not in result
            
        elif task['task_type'] == 'sqlmap_scan':
            scanner = SqlmapScanner()
            result = scanner.scan(normalized_target, target_scope)
            success = "error" not in result
            
        else:
            logger.warning(f"Unknown task type: {task['task_type']}")
            result = {"error": f"Unknown task type: {task['task_type']}"}
            success = False
            
    except Exception as e:
        logger.error(f"Error executing {task['task_type']} on {normalized_target}: {str(e)}")
        result = {"error": str(e)}
        success = False
    
    execution_time = time.time() - start_time
    logger.info(f"Task completed in {execution_time:.2f}s: {task_signature}, success: {success}")
    
    # Only mark task as seen after successful execution
    if success:
        state['seen_tasks'][task_signature] = True
        
        # Record result
        task_result = {
            "task": task,
            "result": result,
            "success": success,
            "execution_time": execution_time,
            "timestamp": time.time()
        }
        
        # Add to completed tasks and store result
        state['completed_tasks'].append(task)
        state['results'][task_signature] = task_result
    else:
        # If task failed, we might want to retry it later
        state['task_queue'].append(task)
    
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
    llm = ChatOpenAI(temperature=0, model="gpt-4o-mini")
    
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
            logger.error(f"Could not parse follow-up tasks from: {response.content}")
            follow_up_tasks = []
    
    # Filter and add follow-up tasks with strict scope validation
    filtered_tasks = []
    target_scope = TargetScope.from_dict(state['target_scope'])
    
    for task in follow_up_tasks:
        task_target = target_scope._normalize_domain(task['target'])
        task_signature = f"{task['task_type']}:{task_target}"
        
        # Skip if the task has already been executed successfully
        if task_signature in state['seen_tasks']:
            logger.info(f"Task {task_signature} already executed successfully, skipping")
            continue
        
        # Skip if the task is already in the queue
        if any(t['task_type'] == task['task_type'] and 
               target_scope._normalize_domain(t['target']) == task_target 
               for t in state['task_queue']):
            # logger.info(f"Task {task_signature} already in queue, skipping")
            continue
        
        # Strict scope validation
        if not target_scope.is_target_allowed(task_target):
            logger.warning(f"Follow-up task for target {task_target} rejected: outside scope {target_scope.allowed_domains}")
            continue
        
        filtered_tasks.append(task)
    
    # Limit number of follow-up tasks to prevent explosion
    max_follow_up_tasks = 5
    filtered_tasks = filtered_tasks[:max_follow_up_tasks]
    
    # Sort by priority and add to queue
    filtered_tasks.sort(key=lambda x: x.get('priority', 3))
    if filtered_tasks:
        # Find the most recent tasks log file
            tasks_log_dir = 'tasks_logs'
            log_files = sorted([f for f in os.listdir(tasks_log_dir) if f.startswith('initial_tasks_')], reverse=True)
            
            if log_files:
                most_recent_log = os.path.join(tasks_log_dir, log_files[0])
                
                # Read existing log
                with open(most_recent_log, 'r') as f:
                    log_data = json.load(f)
                
                # Add follow-up tasks to the log
                if 'follow_up_tasks' not in log_data:
                    log_data['follow_up_tasks'] = []
                
                # Add timestamp and details to follow-up tasks
                for task in filtered_tasks:
                    task['generated_at'] = time.strftime("%Y%m%d_%H%M%S")
                    task['source_task'] = {
                        'type': last_task['task_type'],
                        'target': last_task['target']
                    }
                
                log_data['follow_up_tasks'].extend(filtered_tasks)
                
                # Write back to the file
                with open(most_recent_log, 'w') as f:
                    json.dump(log_data, f, indent=2)
                
                logger.info(f"Follow-up tasks logged to {most_recent_log}")
    
    
    state['task_queue'].extend(filtered_tasks)
    
    logger.info(f"Added {len(filtered_tasks)} follow-up tasks based on results analysis")
    return state


def should_continue(state: SecurityAuditState) -> str:
    """Determine whether to continue executing tasks or finalize the audit."""
    # Check remaining steps
    if state["remaining_steps"] <= 2:
        logger.warning("Maximum steps reached, generating report")
        return "generate_report"
    
    # Check other termination conditions    
    if state.get("task_complete", False):
        return "generate_report"
    if not state['task_queue']:
        return "generate_report"
        
    # Continue with next task
    return "execute_task"


def generate_report(state: SecurityAuditState) -> SecurityAuditState:
    """Generate a comprehensive security report based on all findings."""
    logger.info("Generating security report")
    
    # Set up LLM
    llm = ChatOpenAI(temperature=0, model="gpt-4o-mini")
    
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
    state['task_complete'] = True  # Mark audit as complete
    
    logger.info(f"Security report generated and saved to {report_path}")
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
        report="",
        task_complete=False,
        remaining_steps=50,  # Set maximum number of steps
        seen_tasks={}  # Initialize task deduplication tracking
    )
    
    # Build and run workflow
    workflow = build_security_audit_workflow()
    final_state = workflow.invoke(init_state)
    
    return final_state['report']


# Example usage
if __name__ == "__main__":
    # Define the allowed scope
    print("Hello")
    # allowed_domains = ["example.com", "test.example.com"]
    allowed_domains = ["google.com"]
    allowed_ip_ranges = ["192.168.1.0/24", "10.0.0.0/16"]
    
    # Set the security objective
    # objective = """Perform a comprehensive security assessment of google.com. 
    # Identify open ports, discover hidden directories, and test for common web vulnerabilities 
    # including SQL injection. Ensure all tests are non-intrusive and respect the target scope."""
    objective = "Discover open ports on google.com"
    # Run the security audit
    report = run_security_audit(objective, allowed_domains, allowed_ip_ranges)
    
    print("Security audit completed. Report generated.")
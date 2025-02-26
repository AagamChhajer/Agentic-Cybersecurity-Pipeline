import streamlit as st
import time
from agent_langgraph import run_security_audit, SecurityAuditState
import json
import pandas as pd
from typing import List, Dict
import plotly.express as px
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename='security_pipeline.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def initialize_session_state():
    """Initialize session state variables if they don't exist."""
    if 'audit_running' not in st.session_state:
        st.session_state.audit_running = False
    if 'task_status' not in st.session_state:
        st.session_state.task_status = []
    if 'current_logs' not in st.session_state:
        st.session_state.current_logs = []
    if 'final_report' not in st.session_state:
        st.session_state.final_report = ""

def parse_ip_ranges(ip_ranges_text: str) -> List[str]:
    """Parse IP ranges from text input."""
    return [range_str.strip() for range_str in ip_ranges_text.split('\n') if range_str.strip()]

def parse_domains(domains_text: str) -> List[str]:
    """Parse domains from text input."""
    return [domain.strip() for domain in domains_text.split('\n') if domain.strip()]

def create_task_status_df(task_status: List[Dict]) -> pd.DataFrame:
    """Create a DataFrame from task status list."""
    if not task_status:
        return pd.DataFrame(columns=['Task Type', 'Target', 'Status', 'Duration', 'Timestamp'])
    return pd.DataFrame(task_status)

def display_task_metrics(df: pd.DataFrame):
    """Display task metrics using Streamlit columns."""
    total = len(df)
    completed = len(df[df['Status'] == 'Completed'])
    running = len(df[df['Status'] == 'Running'])
    failed = len(df[df['Status'] == 'Failed'])
    pending = len(df[df['Status'] == 'Pending'])

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Tasks", total)
    with col2:
        st.metric("Completed", completed)
    with col3:
        st.metric("Running", running)
    with col4:
        st.metric("Failed", failed)
    with col5:
        st.metric("Pending", pending)

def create_status_chart(df: pd.DataFrame):
    """Create a status distribution chart using Plotly."""
    status_counts = df['Status'].value_counts()
    fig = px.pie(
        values=status_counts.values,
        names=status_counts.index,
        title='Task Status Distribution',
        color_discrete_map={
            'Completed': '#00CC96',
            'Running': '#FFA15A',
            'Failed': '#EF553B',
            'Pending': '#636EFA'
        }
    )
    return fig

def main():
    st.set_page_config(
        page_title="Security Audit Dashboard",
        page_icon="🔒",
        layout="wide"
    )

    initialize_session_state()

    st.title("🔒 Security Audit Dashboard")

    # Sidebar configuration
    with st.sidebar:
        st.header("Audit Configuration")
        
        objective = st.text_area(
            "Security Audit Objective",
            value="Perform a comprehensive security assessment. Identify open ports, discover hidden directories, and test for common web vulnerabilities.",
            height=100
        )
        
        domains = st.text_area(
            "Target Domains (one per line)",
            value="example.com\ntest.example.com",
            height=100
        )
        
        ip_ranges = st.text_area(
            "Target IP Ranges (one per line)",
            value="192.168.1.0/24\n10.0.0.0/16",
            height=100
        )

        if st.button("Start Security Audit", disabled=st.session_state.audit_running):
            st.session_state.audit_running = True
            st.session_state.task_status = []
            st.session_state.current_logs = []
            st.session_state.final_report = ""

    # Main content area
    if st.session_state.audit_running:
        # Create tabs for different views
        tab1, tab2, tab3 = st.tabs(["Dashboard", "Logs", "Report"])

        with tab1:
            st.header("Task Status Dashboard")
            
            # Create and display task status DataFrame
            df = create_task_status_df(st.session_state.task_status)
            
            # Display metrics
            display_task_metrics(df)
            
            # Create two columns for chart and table
            col1, col2 = st.columns([1, 2])
            
            with col1:
                # Display status distribution chart
                if not df.empty:
                    fig = create_status_chart(df)
                    st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # Display task status table
                if not df.empty:
                    st.dataframe(
                        df.sort_values('Timestamp', ascending=False),
                        use_container_width=True,
                        height=400
                    )

        with tab2:
            st.header("Audit Logs")
            # Display logs in a scrollable container
            log_container = st.container()
            with log_container:
                for log in st.session_state.current_logs:
                    st.text(log)

        with tab3:
            st.header("Security Audit Report")
            if st.session_state.final_report:
                st.markdown(st.session_state.final_report)
            else:
                st.info("The final report will appear here once the audit is complete.")

        # Run the security audit if it's just started
        try:
            parsed_domains = parse_domains(domains)
            parsed_ip_ranges = parse_ip_ranges(ip_ranges)
            
            # Run the security audit
            report = run_security_audit(objective, parsed_domains, parsed_ip_ranges)
            
            # Update session state
            st.session_state.final_report = report
            st.session_state.audit_running = False
            
            # Force refresh
            st.rerun()
            
        except Exception as e:
            st.error(f"An error occurred during the security audit: {str(e)}")
            st.session_state.audit_running = False
            logging.error(f"Security audit failed: {str(e)}")

    else:
        if st.session_state.final_report:
            st.success("Security audit completed!")
            st.markdown(st.session_state.final_report)

if __name__ == "__main__":
    main()
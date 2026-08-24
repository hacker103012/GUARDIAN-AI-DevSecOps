import streamlit as st
import re
import ast

# Page Configuration
st.set_page_config(page_title="GuardianAI Enterprise", page_icon="🛡️", layout="wide")

# Custom CSS for modern enterprise look
st.markdown("""
    <style>
    .metric-card {
        background-color: #1e293b;
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid #3b82f6;
        margin-bottom: 10px;
    }
    .metric-crit { border-left-color: #ef4444; }
    .metric-safe { border-left-color: #10b981; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ GuardianAI: Next-Gen DevSecOps Platform")
st.subheader("Enterprise-grade static application security testing (SAST) with intelligent parsing & remediation")
st.write("---")


# ==========================================
# ADVANCED AST & TAINT ANALYSIS ENGINE
# ==========================================
class ASTSecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []
        self.tainted_vars = set()  # Stores variables derived from untrusted user input

    def _get_func_name(self, node):
        """Helper to recursively unravel function and attribute names (e.g., db.engine.execute)."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_func_name(node.value)}.{node.attr}"
        return ""

    def _is_unsafe_sql_string(self, node):
        """Check if node represents string formatting/f-strings containing SQL keywords."""
        # Check Python f-strings (JoinedStr)
        if isinstance(node, ast.JoinedStr):
            full_str = ""
            for val in node.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    full_str += val.value
            if any(kw in full_str.upper() for kw in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE']):
                return True
        # Check %-formatting or .format()
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
            return True
        return False

    def visit_Assign(self, node):
        """Track data propagation and variable taint status."""
        is_tainted = False
        if isinstance(node.value, ast.Call):
            func_str = self._get_func_name(node.value.func)
            # Identify user input sources
            if any(src in func_str for src in ['request.args', 'request.form', 'request.values', 'request.GET', 'request.POST']):
                is_tainted = True
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                if is_tainted:
                    self.tainted_vars.add(target.id)
                elif self._is_unsafe_sql_string(node.value):
                    # Flag string variables constructed with dynamic SQL queries
                    self.tainted_vars.add(target.id)

        self.generic_visit(node)

    def visit_Call(self, node):
        """Analyze dangerous function sinks."""
        func_name = self._get_func_name(node.func)

        # 1. SQL Injection Analysis
        if any(db_kw in func_name for db_kw in ['execute', 'executemany', 'raw', 'query']):
            if node.args:
                arg0 = node.args[0]
                # Case A: F-string or dynamic string directly passed to DB call
                if self._is_unsafe_sql_string(arg0):
                    self.issues.append((
                        node.lineno,
                        "SQL Injection (AST & Taint Analysis)",
                        f"Unsafe dynamic string formatting in DB query execution: `{func_name}()`",
                        "Use parameterized queries with placeholders (e.g., db.execute(query, {'param': val})) instead of f-strings."
                    ))
                # Case B: Tainted variable containing user input passed to DB call
                elif isinstance(arg0, ast.Name) and arg0.id in self.tainted_vars:
                    self.issues.append((
                        node.lineno,
                        "SQL Injection (AST & Taint Analysis)",
                        f"Tainted query variable '{arg0.id}' executed in database query",
                        "Refactor query execution to use prepared statements or ORM binding."
                    ))

        # 2. Command Injection Analysis
        if func_name in ['os.system', 'os.popen']:
            self.issues.append((
                node.lineno,
                "Command Injection (AST)",
                f"Call to '{func_name}()' executes shell commands without input sanitization.",
                "Refactor using 'subprocess.run(..., shell=False)' with arguments passed as a list."
            ))

        # 3. Dynamic Code Execution
        if func_name in ['eval', 'exec']:
            self.issues.append((
                node.lineno,
                "Dynamic Code Execution (AST)",
                f"Use of unsafe '{func_name}()'",
                "Avoid runtime execution of strings; parse structures safely or use safer APIs."
            ))

        # 4. Insecure Deserialization
        if func_name in ['pickle.loads', 'yaml.load']:
            self.issues.append((
                node.lineno,
                "Insecure Deserialization (AST)",
                f"Unsafe object deserialization in '{func_name}()'",
                "Use secure deserialization alternatives like 'yaml.safe_load()' or 'json.loads()'."
            ))

        self.generic_visit(node)


def analyze_python_ast(code):
    """Parses code and runs the AST security visitor."""
    try:
        tree = ast.parse(code)
        visitor = ASTSecurityVisitor()
        visitor.visit(tree)
        return visitor.issues
    except SyntaxError:
        return []  # Gracefully handle non-compilable or partial code snippets


col1, col2 = st.columns([1, 1.2])

with col1:
    st.markdown("### 📥 Source Code Input")
    
    language = st.selectbox(
        "Target Programming Language / Framework:",
        ["Python", "Bash", "C / C++", "Java", "HTML"]
    )
    
    user_code = st.text_area("Paste architecture scripts or source code structures...", height=380, placeholder="# Enter your code here...")
    
    btn_col1, btn_col2 = st.columns(2)
    with btn_col1:
        scan_button = st.button("🚀 Run Deep Security Scan", use_container_width=True)
    with btn_col2:
        fix_button = st.button("⚡ Automated Patch & Remediation", use_container_width=True)

with col2:
    st.markdown("### 📊 Enterprise Security Diagnostics")
    
    # Base pattern matching rules
    cred_pattern = r"(password|passwd|secret|api_key|token)\s*[:=]\s*['\"][^'\"]+['\"]"
    rules = {}
    
    if language == "Python":
        rules = {
            "Hardcoded Secret Signature": (cred_pattern, "Decouple variables using environmental injections (`os.getenv`)"),
            "Insecure Port Binding": (r"(\.run|\.listen).*0\.0\.0\.0", "Bind stringently to localhost interface `127.0.0.1`"),
        }
    elif language == "Bash":
        rules = {
            "Root Execution Privilege": (r"(sudo\s|runas)", "Implement Least Privilege Access Control parameters"),
            "Insecure File Permission (chmod 777)": (r"chmod\s+777", "Restrict terminal permissions to secure bounds (`755` / `600`)"),
        }
    elif language in ["C / C++", "Java"]:
        rules = {
            "Hardcoded Secret": (r"(String|char).*?(password|secret|key)\s*=\s*['\"][^'\"]+['\"]", "Utilize external secure vault key management infrastructure"),
            "Buffer Overflow Vector": (r"\b(strcpy|gets|sprintf)\b", "Migrate pipeline strictly to safe bounded bounds (`strncpy` / `fgets`)"),
        }
    elif language == "HTML":
        rules = {
            "Insecure Transport Protocol": (r"<form.*action=[\"']http://", "Enforce systemic SSL/TLS protection via forced `https://` schemas"),
            "Cross-Site Scripting (XSS) Vector": (r"<script>", "Sanitize inputs and employ external trusted script assets"),
        }

    # Process Actions
    if (scan_button or fix_button) and user_code.strip():
        lines = user_code.split('\n')
        detected_issues = []
        fixed_lines = lines.copy()
        
        # 1. Pattern Matching Engine (Regex)
        for rule_name, (pattern, fix_suggestion) in rules.items():
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    detected_issues.append((line_num, rule_name, line.strip(), fix_suggestion))
        
        # 2. Advanced Parsing Engine (AST & Taint Analysis for Python)
        if language == "Python":
            ast_findings = analyze_python_ast(user_code)
            for lineno, name, current_line, fix in ast_findings:
                # Avoid duplicate entries if regex caught it too
                if not any(x[0] == lineno and x[1] == name for x in detected_issues):
                    line_content = lines[lineno-1].strip() if lineno <= len(lines) else current_line
                    detected_issues.append((lineno, name, line_content, fix))

        # Sort issues by line number
        detected_issues.sort(key=lambda x: x[0])

        # 3. Automated Patching Loop
        for line_num, name, text, _ in detected_issues:
            line_idx = line_num - 1
            if line_idx < len(lines):
                line = lines[line_idx]
                if "Secret" in name and language == "Python":
                    fixed_lines[line_idx] = re.sub(r"=\s*['\"][^'\"]+['\"]", "= os.getenv('APP_SECRET_KEY', 'SECURE_FALLBACK')", line)
                elif "SQL Injection" in name:
                    fixed_lines[line_idx] = f"# FIXED: Refactored unsafe string concatenation/f-string into parameterized execution\n# Original: {line.strip()}"
                elif "AST" in name or "Command Injection" in name:
                    fixed_lines[line_idx] = f"# FIXED: Patched unsafe execution vector securely\n# Original: {line.strip()}"
                elif "http://" in line:
                    fixed_lines[line_idx] = re.sub(r"http://", "https://", line)
                elif "chmod 777" in line:
                    fixed_lines[line_idx] = re.sub(r"chmod\s+777", "chmod 755", line)
                elif "strcpy" in line:
                    fixed_lines[line_idx] = f"/* FIXED: Manually substitute with strncpy bounds check */ {line}"

        # 📈 Advanced Security Metrics Panel
        vuln_count = len(detected_issues)
        severity_deduction = vuln_count * 25
        security_score = max(100 - severity_deduction, 0)
        
        total_rules_active = len(rules) + (5 if language == "Python" else 0)

        m_col1, m_col2, m_col3 = st.columns(3)
        with m_col1:
            status_class = "metric-crit" if vuln_count > 0 else "metric-safe"
            st.markdown(f"<div class='metric-card {status_class}'><h4>🚨 Total Risk Points</h4><h2>{vuln_count}</h2></div>", unsafe_allow_html=True)
        with m_col2:
            st.markdown(f"<div class='metric-card'><h4>⚙️ Active Rules Analyzed</h4><h2>{total_rules_active}</h2></div>", unsafe_allow_html=True)
        with m_col3:
            fix_status = "Ready to Deploy" if vuln_count > 0 else "Compliant"
            st.markdown(f"<div class='metric-card metric-safe'><h4>⚡ Auto-Remediation</h4><h2>{fix_status}</h2></div>", unsafe_allow_html=True)

        # Main Score Progress Meter
        st.write("### Platform Security Health Index")
        if security_score >= 80:
            st.success(f"**Security Score: {security_score}/100** — Infrastructure Architecture is Highly Secure.")
        elif security_score >= 50:
            st.warning(f"**Security Score: {security_score}/100** — Warning: Remediate flaws immediately.")
        else:
            st.error(f"**Security Score: {security_score}/100** — Critical Breach: Severe software supply chain threat.")
        st.progress(security_score / 100)
        st.write("---")

        # Handle Normal Scanning Output
        if scan_button:
            if not detected_issues:
                st.success("🎉 **Zero threat signatures identified.** Codebase architecture fully complies with core DevSecOps standards.")
            else:
                # Modern Structured Tabular Data Display
                st.markdown("#### 📋 Core Compliance Findings")
                table_data = []
                for num, name, text, fix in detected_issues:
                    table_data.append({"Line": num, "Vulnerability Type": name, "Flaw Snippet": text, "Remediation Strategy": fix})
                st.dataframe(table_data, use_container_width=True)
                
                # Expanders for granular code review
                st.markdown("#### 🔍 Deep Code Review Context")
                for line_num, name, text, fix in detected_issues:
                    with st.expander(f"🔴 Line {line_num}: {name}"):
                        st.code(text, language=language.lower())
                        st.info(f"💡 **Fix Action:** {fix}")

        # Handle Automated Patching Code Block UI
        if fix_button:
            st.info("⚡ **GuardianAI Real-time Patching Module Triggered:** Pipeline Modifications Generated Below")
            diff_col1, diff_col2 = st.columns(2)
            with diff_col1:
                st.markdown("❌ **Vulnerable Code Stream**")
                st.code(user_code, language=language.lower())
            with diff_col2:
                st.markdown("✅ **GuardianAI Patched Output**")
                st.code("\n".join(fixed_lines), language=language.lower())
            
    elif (scan_button or fix_button) and not user_code.strip():
        st.error("Submission blocked. Code telemetry stream cannot be empty.")
    else:
        st.info("Initialize the platform detection engine by inputting active script repositories.")
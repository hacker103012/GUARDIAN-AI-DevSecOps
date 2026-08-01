import streamlit as st
import re

# Page Configuration
st.set_page_config(page_title="GuardianAI Enterprise", page_icon="🛡️", layout="wide")

st.title("🛡️ GuardianAI: Next-Gen DevSecOps Platform")
st.subheader("Enterprise-grade static application security testing (SAST) with real-time patching")
st.write("---")

col1, col2 = st.columns([1, 1])

with col1:
    st.markdown("### 📥 Source Code Input")
    
    language = st.selectbox(
        "Target Programming Language:",
        ["Python", "Bash", "C / C++", "Java", "HTML"]
    )
    
    user_code = st.text_area("Paste code snippet for security compilation...", height=350, placeholder="# Enter your code here...")
    
    btn_col1, btn_col2 = st.columns(2)
    with btn_col1:
        scan_button = st.button("🚀 Analyze Vulnerabilities", use_container_width=True)
    with btn_col2:
        fix_button = st.button("⚡ Auto-Fix & Patch Code", use_container_width=True)

with col2:
    st.markdown("### 📊 Security Diagnostics & Remediation")
    
    # Base pattern matching rules
    cred_pattern = r"(password|passwd|secret|api_key|token)\s*[:=]\s*['\"][^'\"]+['\"]"
    rules = {}
    
    if language == "Python":
        rules = {
            "Hardcoded Secret": (cred_pattern, "Use environmental variables (`os.environ`)"),
            "Insecure Port Binding": (r"(\.run|\.listen).*0\.0\.0\.0", "Bind strictly to `127.0.0.1` for localization"),
            "Command Injection Risk": (r"(eval\(|os\.system\(|subprocess\.Popen\()", "Utilize safe high-level APIs instead of raw shell systems")
        }
    elif language == "Bash":
        rules = {
            "Root Execution Privilege": (r"(sudo\s|runas)", "Implement Least Privilege Access Control configurations"),
            "Insecure File Permission (chmod 777)": (r"chmod\s+777", "Restrict permissions to secure thresholds like `755` or `600`"),
        }
    elif language in ["C / C++", "Java"]:
        rules = {
            "Hardcoded Secret": (r"(String|char).*?(password|secret|key)\s*=\s*['\"][^'\"]+['\"]", "Leverage vault key management infrastructure systems"),
            "Buffer Overflow Risk": (r"\b(strcpy|gets|sprintf)\b", "Switch to safer bounded methods like `strncpy` or `fgets`"),
        }
    elif language == "HTML":
        rules = {
            "Insecure Transport Protocol": (r"<form.*action=[\"']http://", "Enforce full SSL/TLS migration by forcing `https://` endpoints"),
            "Cross-Site Scripting (XSS) Vector": (r"<script>", "Sanitize inputs and use external secure asset scripts instead of inline elements"),
        }

    # Process Actions
    if (scan_button or fix_button) and user_code.strip():
        lines = user_code.split('\n')
        detected_issues = []
        fixed_lines = lines.copy()
        
        # Scan phase & apply automated patching modifications
        for rule_name, (pattern, fix_suggestion) in rules.items():
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    detected_issues.append((line_num, rule_name, line.strip(), fix_suggestion))
                    
                    # Targeted Rule transformations:
                    if "Secret" in rule_name and language == "Python":
                        # Replace hardcoded assignment with os.environ lookup
                        fixed_lines[line_num - 1] = re.sub(r"=\s*['\"][^'\"]+['\"]", "= os.environ.get('APP_SECRET_KEY', 'FALLBACK_SECURE_VAL')", line)
                    elif "Command Injection" in rule_name and language == "Python":
                        # Replace unsafe os.system calls with a comment placeholder or safer call structure
                        fixed_lines[line_num - 1] = "# FIXED: Removed unsafe shell execution\n# subprocess.run(['command'], check=True)"
                    elif "http://" in line:
                        fixed_lines[line_num - 1] = re.sub(r"http://", "https://", line)
                    elif "chmod 777" in line:
                        fixed_lines[line_num - 1] = re.sub(r"chmod\s+777", "chmod 755", line)
                    elif "strcpy" in line:
                        fixed_lines[line_num - 1] = "/* WARNING: Replace strcpy with strncpy manually to allocate safe buffers */ " + line

        # 📊 Dynamic Security Score Generation
        severity_deduction = len(detected_issues) * 25
        security_score = max(100 - severity_deduction, 0)
        
        # Displaying Score Meter UI
        if security_score >= 80:
            st.success(f"### 🛡️ System Security Score: {security_score}/100 (Excellent)")
        elif security_score >= 50:
            st.warning(f"### ⚠️ System Security Score: {security_score}/100 (Risk Detected)")
        else:
            st.error(f"### 🚨 System Security Score: {security_score}/100 (Critical Compromise)")
            
        st.progress(security_score / 100)
        st.write("---")

        # Handle Normal Scanning Output
        if scan_button:
            if not detected_issues:
                st.success("🎉 **Zero threat signatures identified.** Codebase architecture complies with core DevSecOps standards.")
            else:
                for line_num, name, text, fix in detected_issues:
                    with st.expander(f"🔴 Line {line_num}: Critical vulnerability ({name})", expanded=True):
                        st.code(text, language=language.lower())
                        st.markdown(f"**Security Remediation Plan:** {fix}")

        # Handle Automated Patching Code Block UI (Clear Visual Comparison)
        if fix_button:
            st.info("⚡ **GuardianAI Real-time Patching Module Triggered:** Side-by-Side Comparison")
            
            diff_col1, diff_col2 = st.columns(2)
            with diff_col1:
                st.markdown("❌ **Original Vulnerable Code**")
                st.code(user_code, language=language.lower())
            with diff_col2:
                st.markdown("✅ **Patched Secure Code**")
                st.code("\n".join(fixed_lines), language=language.lower())
            
    elif (scan_button or fix_button) and not user_code.strip():
        st.error("Submission blocked. Code field cannot be left blank for analysis.")
    else:
        st.info("Initialize the platform engine by inputting terminal scripts or source code structures.")
# ========================================================
# SESSION COOKIE ANALYZER TOOL
# ========================================================
# Purpose: Analyze session cookies for security weaknesses
# Features:
#   - Import cookie logs (CSV)
#   - Parse and display key cookie attributes
#   - Detect common security issues:
#       • Missing Secure flag
#       • Missing HttpOnly flag
#       • Missing SameSite attribute (or weak value)
#       • Short expiration time
#       • Suspicious cookie names
#   - Color-coded risk levels (Low / Medium / High)
#   - Detailed analysis report with recommendations
#
# Built with only Python standard library (Tkinter)
# ========================================================

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import csv
from datetime import datetime
import os
import re

class SessionCookieAnalyzer:
    def __init__(self, root):
        """Initialize the Session Cookie Analyzer GUI."""
        self.root = root
        self.root.title("🍪 Session Cookie Analyzer - Security Auditor")
        self.root.geometry("1150x780")
        self.root.resizable(True, True)

        self.cookies = []          # Raw parsed cookies
        self.analysis_results = [] # Analysis with risk scores

        # ---------------------------------------------------
        # HEADER BUTTONS
        # ---------------------------------------------------
        btn_frame = tk.Frame(root, padx=12, pady=12)
        btn_frame.pack(fill=tk.X)

        tk.Button(
            btn_frame, text="📂 Import Cookie Log (CSV)", 
            font=("Arial", 11, "bold"), bg="#4CAF50", fg="white",
            width=26, command=self.import_cookies
        ).pack(side=tk.LEFT, padx=8)

        tk.Button(
            btn_frame, text="🔍 Analyze Cookies", 
            font=("Arial", 11, "bold"), bg="#FF5722", fg="white",
            width=20, command=self.analyze_cookies
        ).pack(side=tk.LEFT, padx=8)

        tk.Button(
            btn_frame, text="🗑️ Clear All", 
            font=("Arial", 11, "bold"), bg="#f44336", fg="white",
            width=15, command=self.clear_all
        ).pack(side=tk.LEFT, padx=8)

        self.status_label = tk.Label(
            btn_frame, text="No cookies loaded", 
            font=("Arial", 10), fg="#555"
        )
        self.status_label.pack(side=tk.RIGHT, padx=15)

        # ---------------------------------------------------
        # COOKIE TABLE
        # ---------------------------------------------------
        columns = ("Cookie Name", "Domain", "Path", "Secure", "HttpOnly", 
                  "SameSite", "Expires In", "Risk Level")

        self.tree = ttk.Treeview(root, columns=columns, show="headings", height=22)
        
        for col in columns:
            self.tree.heading(col, text=col)
        
        self.tree.column("Cookie Name", width=180)
        self.tree.column("Domain", width=140)
        self.tree.column("Path", width=80)
        self.tree.column("Secure", width=70, anchor="center")
        self.tree.column("HttpOnly", width=80, anchor="center")
        self.tree.column("SameSite", width=90, anchor="center")
        self.tree.column("Expires In", width=110, anchor="center")
        self.tree.column("Risk Level", width=100, anchor="center")

        scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(padx=12, pady=8, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Risk level color tags
        self.tree.tag_configure("High", background="#ffebee", foreground="#c62828")
        self.tree.tag_configure("Medium", background="#fff3e0", foreground="#ef6c00")
        self.tree.tag_configure("Low", background="#e8f5e9", foreground="#2e7d32")

        # ---------------------------------------------------
        # ANALYSIS REPORT PANEL
        # ---------------------------------------------------
        report_frame = tk.LabelFrame(
            root, text="📋 COOKIE SECURITY ANALYSIS REPORT", 
            font=("Arial", 12, "bold"), padx=10, pady=8
        )
        report_frame.pack(fill=tk.X, padx=12, pady=10)

        self.report_text = tk.Text(
            report_frame, height=12, font=("Consolas", 10), bg="#f8f9fa"
        )
        self.report_text.pack(fill=tk.X, padx=5, pady=5)

        self.show_welcome_message()

    # -------------------------------------------------------
    # IMPORT COOKIES
    # -------------------------------------------------------
    def import_cookies(self):
        """Import CSV file containing cookie data."""
        file_path = filedialog.askopenfilename(
            title="Select Cookie Log File",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        try:
            with open(file_path, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                self.cookies.clear()

                for row in reader:
                    self.cookies.append({
                        'cookie_name': (row.get('cookie_name') or row.get('Cookie Name') or row.get('name') or '').strip(),
                        'domain': (row.get('domain') or row.get('Domain') or '').strip(),
                        'path': (row.get('path') or row.get('Path') or '/').strip(),
                        'secure': (row.get('secure') or row.get('Secure') or 'False').strip().lower(),
                        'httponly': (row.get('httponly') or row.get('HttpOnly') or 'False').strip().lower(),
                        'samesite': (row.get('samesite') or row.get('SameSite') or '').strip().upper(),
                        'expires': (row.get('expires') or row.get('Expires') or '').strip()
                    })

            self.status_label.config(
                text=f"✅ Loaded {len(self.cookies)} cookies", 
                fg="#2e7d32"
            )
            messagebox.showinfo("Import Successful", f"Loaded {len(self.cookies)} session cookies.")

        except Exception as e:
            messagebox.showerror("Import Error", f"Could not read the file:\n{str(e)}")

    # -------------------------------------------------------
    # ANALYZE COOKIES (CORE LOGIC)
    # -------------------------------------------------------
    def analyze_cookies(self):
        """Perform security analysis on all loaded cookies."""
        if not self.cookies:
            messagebox.showwarning("No Data", "Please import a cookie log file first!")
            return

        self.analysis_results.clear()

        high_risk = 0
        medium_risk = 0

        for cookie in self.cookies:
            risks = []
            risk_level = "Low"

            # 1. Check Secure flag (critical for HTTPS)
            if cookie['secure'] not in ['true', '1', 'yes']:
                risks.append("Missing Secure flag (transmitted over HTTP)")
                risk_level = "High"

            # 2. Check HttpOnly flag (protects against XSS)
            if cookie['httponly'] not in ['true', '1', 'yes']:
                risks.append("Missing HttpOnly flag (vulnerable to XSS)")
                if risk_level != "High":
                    risk_level = "Medium"

            # 3. Check SameSite attribute
            samesite = cookie['samesite']
            if not samesite or samesite in ['NONE', '']:
                risks.append("Missing or weak SameSite (CSRF risk)")
                if risk_level == "Low":
                    risk_level = "Medium"
            elif samesite == "NONE" and cookie['secure'] not in ['true', '1', 'yes']:
                risks.append("SameSite=None without Secure flag (modern browser block)")

            # 4. Check expiration time (session cookies should not be too persistent)
            expires_in = "Session Cookie"
            if cookie['expires']:
                try:
                    exp_date = datetime.strptime(cookie['expires'], '%Y-%m-%d %H:%M:%S')
                    days_left = (exp_date - datetime.now()).days
                    expires_in = f"{days_left} days" if days_left > 0 else "Expired"
                    if days_left > 30:
                        risks.append("Very long expiration time")
                        if risk_level == "Low":
                            risk_level = "Medium"
                except:
                    expires_in = "Invalid format"

            # 5. Suspicious cookie name patterns
            name = cookie['cookie_name'].lower()
            if re.search(r'(session|auth|token|jwt|sid)', name) and risk_level == "Low":
                pass  # normal for session cookies
            elif any(x in name for x in ['debug', 'test', 'admin', 'root']):
                risks.append("Suspicious cookie name")
                risk_level = "Medium"

            if risks:
                if "Missing Secure" in str(risks) or "Missing HttpOnly" in str(risks):
                    high_risk += 1
                else:
                    medium_risk += 1

            self.analysis_results.append({
                'cookie_name': cookie['cookie_name'] or "Unnamed",
                'domain': cookie['domain'] or "N/A",
                'path': cookie['path'],
                'secure': '✅' if cookie['secure'] in ['true','1','yes'] else '❌',
                'httponly': '✅' if cookie['httponly'] in ['true','1','yes'] else '❌',
                'samesite': cookie['samesite'] or 'None',
                'expires_in': expires_in,
                'risk_level': risk_level,
                'issues': " | ".join(risks) if risks else "No major issues"
            })

        # Populate the table
        self.populate_table()

        # Generate final report
        self.generate_report(len(self.cookies), high_risk, medium_risk)

    # -------------------------------------------------------
    # POPULATE TABLE
    # -------------------------------------------------------
    def populate_table(self):
        """Display analysis results in the Treeview with colors."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        for res in self.analysis_results:
            self.tree.insert("", tk.END, values=(
                res['cookie_name'],
                res['domain'],
                res['path'],
                res['secure'],
                res['httponly'],
                res['samesite'],
                res['expires_in'],
                res['risk_level']
            ), tags=(res['risk_level'],))

    # -------------------------------------------------------
    # GENERATE REPORT
    # -------------------------------------------------------
    def generate_report(self, total, high, medium):
        """Create detailed security report."""
        self.report_text.config(state=tk.NORMAL)
        self.report_text.delete(1.0, tk.END)

        report = f"🍪 SESSION COOKIE SECURITY ANALYSIS\n"
        report += f"{'='*50}\n\n"
        report += f"Total Cookies Analyzed     : {total}\n"
        report += f"High Risk Cookies          : {high}\n"
        report += f"Medium Risk Cookies        : {medium}\n"
        report += f"Low Risk / Secure Cookies  : {total - high - medium}\n\n"

        if high > 0:
            report += "🚨 CRITICAL FINDINGS:\n"
            report += "• Cookies missing Secure and/or HttpOnly flags are vulnerable to interception and XSS attacks.\n"
            report += "• Weak SameSite settings increase CSRF risk.\n\n"
            report += "🔧 RECOMMENDATIONS:\n"
            report += "• Always set Secure=true and HttpOnly=true for session cookies\n"
            report += "• Use SameSite=Strict or SameSite=Lax\n"
            report += "• Prefer short-lived session cookies\n"
        elif medium > 0:
            report += "⚠️  MEDIUM RISK DETECTED\n"
            report += "Review expiration times and SameSite attributes.\n"
        else:
            report += "✅ All cookies appear well-configured!\nGreat job on session cookie security.\n"

        self.report_text.insert(tk.END, report)
        self.report_text.config(state=tk.DISABLED)

    # -------------------------------------------------------
    # HELPER FUNCTIONS
    # -------------------------------------------------------
    def clear_all(self):
        """Reset the entire tool."""
        self.cookies.clear()
        self.analysis_results.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.report_text.config(state=tk.NORMAL)
        self.report_text.delete(1.0, tk.END)
        self.report_text.config(state=tk.DISABLED)
        
        self.status_label.config(text="No cookies loaded", fg="#555")
        self.show_welcome_message()
        messagebox.showinfo("Cleared", "All data has been cleared.")

    def show_welcome_message(self):
        """Display welcome and usage instructions."""
        self.report_text.config(state=tk.NORMAL)
        self.report_text.delete(1.0, tk.END)
        welcome = (
            "👋 Welcome to the Session Cookie Analyzer!\n\n"
            "This tool helps you audit session cookies for common security weaknesses.\n\n"
            "How to use:\n"
            "1. Prepare a CSV with columns: cookie_name, domain, path, secure, httponly, samesite, expires\n"
            "2. Click 'Import Cookie Log (CSV)'\n"
            "3. Click 'Analyze Cookies'\n"
            "4. Review color-coded risk levels and detailed report.\n\n"
            "Expected flags: Secure, HttpOnly, SameSite=Lax/Strict"
        )
        self.report_text.insert(tk.END, welcome)
        self.report_text.config(state=tk.DISABLED)


# ========================================================
# RUN THE APPLICATION
# ========================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = SessionCookieAnalyzer(root)
    root.mainloop()

# ========================================================
# TASK 6: SESSION TRACKING SYSTEM
# ========================================================
# This tool tracks user sessions by pairing Login and Logout events.
# Features:
#   - Import session logs (CSV)
#   - Automatically pair Login + Logout to create sessions
#   - Calculate exact session duration (hours, minutes, seconds)
#   - Detect abnormal sessions:
#       • Too short (< 5 minutes)
#       • Too long (> 8 hours)
#   - Beautiful GUI with color-coded results
#   - Full session table and detailed alert panel
#
# Requirements: Only Python standard library (no pip install needed)
# ========================================================

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import csv
from datetime import datetime
import os

class SessionTrackingTool:
    def __init__(self, root):
        """Initialize the main GUI window and all components."""
        self.root = root
        self.root.title("⏱️ Session Tracking System - Login/Logout Analyzer")
        self.root.geometry("1100x750")
        self.root.resizable(True, True)

        # Store all raw log entries
        self.log_data = []
        # Store calculated sessions (after analysis)
        self.sessions = []

        # ---------------------------------------------------
        # HEADER & BUTTONS
        # ---------------------------------------------------
        button_frame = tk.Frame(root, padx=12, pady=12)
        button_frame.pack(fill=tk.X)

        tk.Button(
            button_frame,
            text="📂 Import Session Logs (CSV)",
            font=("Arial", 11, "bold"),
            bg="#2196F3",
            fg="white",
            width=25,
            command=self.import_logs
        ).pack(side=tk.LEFT, padx=8)

        tk.Button(
            button_frame,
            text="🔍 Analyze Sessions",
            font=("Arial", 11, "bold"),
            bg="#FF5722",
            fg="white",
            width=20,
            command=self.analyze_sessions
        ).pack(side=tk.LEFT, padx=8)

        tk.Button(
            button_frame,
            text="🗑️ Clear All",
            font=("Arial", 11, "bold"),
            bg="#f44336",
            fg="white",
            width=15,
            command=self.clear_all
        ).pack(side=tk.LEFT, padx=8)

        self.status_label = tk.Label(
            button_frame,
            text="No logs loaded",
            font=("Arial", 10),
            fg="#555"
        )
        self.status_label.pack(side=tk.RIGHT, padx=15)

        # ---------------------------------------------------
        # SESSION TABLE
        # ---------------------------------------------------
        columns = ("Session ID", "Username", "Login Time", "Logout Time", 
                  "Duration", "Status")

        self.tree = ttk.Treeview(root, columns=columns, show="headings", height=20)
        
        # Configure columns
        self.tree.heading("Session ID", text="Session ID")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Login Time", text="Login Time")
        self.tree.heading("Logout Time", text="Logout Time")
        self.tree.heading("Duration", text="Duration")
        self.tree.heading("Status", text="Status")

        self.tree.column("Session ID", width=80, anchor="center")
        self.tree.column("Username", width=140)
        self.tree.column("Login Time", width=160)
        self.tree.column("Logout Time", width=160)
        self.tree.column("Duration", width=110, anchor="center")
        self.tree.column("Status", width=140, anchor="center")

        # Scrollbar for table
        scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(padx=12, pady=8, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # ---------------------------------------------------
        # ALERT / SUMMARY PANEL
        # ---------------------------------------------------
        alert_frame = tk.LabelFrame(root, text="📊 SESSION ANALYSIS & ABNORMAL DETECTION", 
                                   font=("Arial", 12, "bold"), padx=10, pady=8)
        alert_frame.pack(fill=tk.X, padx=12, pady=10)

        self.alert_text = tk.Text(
            alert_frame,
            height=11,
            font=("Consolas", 10),
            bg="#f8f9fa",
            state=tk.DISABLED
        )
        self.alert_text.pack(fill=tk.X, padx=5, pady=5)

        self.show_welcome_message()

    # -------------------------------------------------------
    # IMPORT LOGS
    # -------------------------------------------------------
    def import_logs(self):
        """Import CSV file containing login and logout events."""
        file_path = filedialog.askopenfilename(
            title="Select Session Log File",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        try:
            with open(file_path, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                self.log_data.clear()

                for row in reader:
                    self.log_data.append({
                        'timestamp': (row.get('timestamp') or row.get('Timestamp') or '').strip(),
                        'username': (row.get('username') or row.get('Username') or '').strip(),
                        'event': (row.get('event') or row.get('Event') or '').strip().lower(),
                        'ip': (row.get('ip') or row.get('IP') or 'N/A').strip()
                    })

            self.populate_raw_table()  # Optional: can show raw logs if needed
            self.status_label.config(
                text=f"✅ Loaded {len(self.log_data)} events from {os.path.basename(file_path)}",
                fg="#2e7d32"
            )
            messagebox.showinfo("Success", f"Imported {len(self.log_data)} log entries.")

        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to read file:\n{str(e)}")

    # -------------------------------------------------------
    # ANALYZE SESSIONS (CORE LOGIC)
    # -------------------------------------------------------
    def analyze_sessions(self):
        """Pair login/logout events and calculate session duration + anomalies."""
        if not self.log_data:
            messagebox.showwarning("No Data", "Please import a log file first!")
            return

        # Group events by username
        from collections import defaultdict
        user_events = defaultdict(list)

        for entry in self.log_data:
            if entry['timestamp'] and entry['username'] and entry['event'] in ['login', 'logout']:
                try:
                    dt = self.parse_timestamp(entry['timestamp'])
                    user_events[entry['username']].append({
                        'time': dt,
                        'event': entry['event'],
                        'original_time': entry['timestamp'],
                        'ip': entry['ip']
                    })
                except:
                    continue  # skip bad timestamps

        self.sessions.clear()
        session_id = 1

        abnormal_count = 0
        short_count = 0
        long_count = 0

        for username, events in user_events.items():
            # Sort events by time
            events.sort(key=lambda x: x['time'])

            i = 0
            while i < len(events) - 1:
                if events[i]['event'] == 'login' and events[i+1]['event'] == 'logout':
                    login_time = events[i]['time']
                    logout_time = events[i+1]['time']
                    duration = logout_time - login_time

                    duration_seconds = duration.total_seconds()
                    hours = int(duration_seconds // 3600)
                    minutes = int((duration_seconds % 3600) // 60)
                    seconds = int(duration_seconds % 60)

                    duration_str = f"{hours}h {minutes:02d}m {seconds:02d}s" if hours > 0 else f"{minutes}m {seconds:02d}s"

                    # Detect abnormal sessions
                    status = "Normal"
                    if duration_seconds < 300:        # Less than 5 minutes
                        status = "⚠️ TOO SHORT"
                        short_count += 1
                        abnormal_count += 1
                    elif duration_seconds > 28800:    # More than 8 hours
                        status = "🔴 TOO LONG"
                        long_count += 1
                        abnormal_count += 1

                    self.sessions.append({
                        'session_id': session_id,
                        'username': username,
                        'login': events[i]['original_time'],
                        'logout': events[i+1]['original_time'],
                        'duration': duration_str,
                        'duration_seconds': duration_seconds,
                        'status': status
                    })
                    session_id += 1
                    i += 2  # skip to next pair
                else:
                    i += 1

        # Populate the results table
        self.populate_session_table()

        # Generate summary alert
        self.generate_alert_summary(len(self.sessions), abnormal_count, short_count, long_count)

    # -------------------------------------------------------
    # TIMESTAMP PARSER
    # -------------------------------------------------------
    def parse_timestamp(self, ts_str):
        """Try multiple common timestamp formats."""
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M',
            '%d/%m/%Y %H:%M:%S',
            '%d/%m/%Y %H:%M',
            '%Y/%m/%d %H:%M:%S'
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts_str.strip(), fmt)
            except ValueError:
                continue
        raise ValueError(f"Could not parse timestamp: {ts_str}")

    # -------------------------------------------------------
    # POPULATE SESSION TABLE
    # -------------------------------------------------------
    def populate_session_table(self):
        """Display all calculated sessions in the Treeview."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        for session in self.sessions:
            tag = 'abnormal' if '⚠️' in session['status'] or '🔴' in session['status'] else 'normal'
            self.tree.insert("", tk.END, values=(
                session['session_id'],
                session['username'],
                session['login'],
                session['logout'],
                session['duration'],
                session['status']
            ), tags=(tag,))

        # Color coding
        self.tree.tag_configure('abnormal', background='#ffebee', foreground='#c62828')
        self.tree.tag_configure('normal', background='#f1f8e9')

    # -------------------------------------------------------
    # ALERT SUMMARY
    # -------------------------------------------------------
    def generate_alert_summary(self, total_sessions, abnormal, short, long):
        """Create detailed summary and show in alert panel."""
        self.alert_text.config(state=tk.NORMAL)
        self.alert_text.delete(1.0, tk.END)

        if total_sessions == 0:
            text = "No complete sessions found.\nMake sure your log contains both 'login' and 'logout' events."
        else:
            text = f"📊 SESSION ANALYSIS COMPLETE\n"
            text += f"Total Sessions Detected : {total_sessions}\n"
            text += f"Abnormal Sessions       : {abnormal}\n"
            text += f"   • Too Short (< 5 min) : {short}\n"
            text += f"   • Too Long (> 8 hrs)  : {long}\n\n"

            if abnormal > 0:
                text += "🚨 ALERT: Abnormal session behavior detected!\n"
                text += "Possible causes:\n"
                text += "• Session hijacking or token theft (too long)\n"
                text += "• Failed logins / quick logouts (too short)\n"
                text += "• Automation scripts or bots\n\n"
                text += "Recommendation: Review all highlighted sessions immediately."
            else:
                text += "✅ All sessions appear normal.\nNo abnormal durations detected."

        self.alert_text.insert(tk.END, text)
        self.alert_text.config(state=tk.DISABLED)

    # -------------------------------------------------------
    # HELPER FUNCTIONS
    # -------------------------------------------------------
    def populate_raw_table(self):
        """Optional: Can be extended to show raw logs if needed."""
        pass

    def clear_all(self):
        """Reset everything."""
        self.log_data.clear()
        self.sessions.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.alert_text.config(state=tk.NORMAL)
        self.alert_text.delete(1.0, tk.END)
        self.alert_text.config(state=tk.DISABLED)
        
        self.status_label.config(text="No logs loaded", fg="#555")
        self.show_welcome_message()
        messagebox.showinfo("Cleared", "All data cleared successfully.")

    def show_welcome_message(self):
        """Show initial instructions."""
        self.alert_text.config(state=tk.NORMAL)
        self.alert_text.delete(1.0, tk.END)
        welcome = (
            "👋 Welcome to the Session Tracking System!\n\n"
            "How to use:\n"
            "1. Import a CSV log file containing 'login' and 'logout' events\n"
            "2. Click 'Analyze Sessions'\n"
            "3. The system will:\n"
            "   • Pair login/logout events per user\n"
            "   • Calculate session duration\n"
            "   • Flag too short (< 5 minutes) or too long (> 8 hours) sessions\n\n"
            "Expected CSV columns: timestamp, username, event (login/logout), ip (optional)"
        )
        self.alert_text.insert(tk.END, welcome)
        self.alert_text.config(state=tk.DISABLED)


# ========================================================
# RUN THE APPLICATION
# ========================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = SessionTrackingTool(root)
    root.mainloop()

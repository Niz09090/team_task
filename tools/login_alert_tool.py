import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from datetime import datetime
import re
import random

class TimeBasedLoginAlertTool:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Time-Based Login Alert System - With Log File Support")
        self.root.geometry("1000x750")
        self.root.configure(bg="#f0f0f0")

        self.attempts = []

        self.create_widgets()

    def create_widgets(self):
        title = tk.Label(self.root, text="Time-Based Login Alert System", 
                        font=("Helvetica", 18, "bold"), bg="#f0f0f0", fg="#333")
        title.pack(pady=15)

        # Control Buttons
        control_frame = tk.Frame(self.root, bg="#f0f0f0")
        control_frame.pack(pady=10, fill="x", padx=20)

        tk.Button(control_frame, text="🔄 Simulate Random Attempt", 
                 command=self.simulate_login, bg="#4CAF50", fg="white", 
                 font=("Helvetica", 10, "bold"), width=28).pack(side="left", padx=5)

        tk.Button(control_frame, text="📂 Load Log File", 
                 command=self.load_log_file, bg="#FF9800", fg="white", 
                 font=("Helvetica", 10, "bold"), width=28).pack(side="left", padx=5)

        tk.Button(control_frame, text="➕ Add Manual Attempt", 
                 command=self.add_manual_attempt, bg="#2196F3", fg="white", 
                 font=("Helvetica", 10, "bold"), width=28).pack(side="left", padx=5)

        tk.Button(control_frame, text="Clear All", 
                 command=self.clear_attempts, bg="#f44336", fg="white", 
                 font=("Helvetica", 10, "bold"), width=15).pack(side="right", padx=5)

        # Treeview for results
        columns = ("Timestamp", "Username", "IP Address", "Status", "Alert")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=18)

        self.tree.heading("Timestamp", text="Timestamp")
        self.tree.heading("Username", text="Username")
        self.tree.heading("IP Address", text="IP Address")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Alert", text="Alert")

        self.tree.column("Timestamp", width=180, anchor="center")
        self.tree.column("Username", width=120, anchor="center")
        self.tree.column("IP Address", width=140, anchor="center")
        self.tree.column("Status", width=100, anchor="center")
        self.tree.column("Alert", width=80, anchor="center")

        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(pady=10, padx=20, fill="both", expand=True)
        scrollbar.pack(side="right", fill="y", padx=(0, 20))

        # Alert Status
        self.alert_label = tk.Label(self.root, text="No alerts yet", 
                                   font=("Helvetica", 12, "bold"), bg="#f0f0f0", fg="green", height=2)
        self.alert_label.pack(pady=8, fill="x", padx=20)

        # Log Output
        self.log_text = scrolledtext.ScrolledText(self.root, height=9, state="disabled", 
                                                 bg="#1e1e1e", fg="#00ff9d", font=("Consolas", 10))
        self.log_text.pack(pady=10, padx=20, fill="both", expand=False)

        footer = tk.Label(self.root, text="Loads log files and detects login attempts between 00:00 - 06:00", 
                         font=("Helvetica", 9), bg="#f0f0f0", fg="#666")
        footer.pack(pady=5)

    def log_message(self, message):
        self.log_text.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{ts}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def is_night_time(self, time_str):
        try:
            # Try multiple date formats
            for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%b %d %H:%M:%S", "%d/%m/%Y %H:%M:%S"]:
                try:
                    dt = datetime.strptime(time_str, fmt)
                    if 0 <= dt.hour < 6:
                        return True
                    break
                except:
                    continue
        except:
            pass
        return False

    def add_attempt(self, timestamp, username, ip, status):
        alert = "🚨 NIGHT" if self.is_night_time(timestamp) else ""
        self.attempts.append((timestamp, username, ip, status, alert))

        self.tree.insert("", "end", values=(timestamp, username, ip, status, alert))

        if alert:
            self.alert_label.config(text="🚨 NIGHT-TIME LOGIN ALERT ACTIVE!", fg="red", bg="#ffebee")
            messagebox.showwarning("Security Alert", 
                f"UNUSUAL NIGHT LOGIN DETECTED!\n\n"
                f"Time     : {timestamp}\n"
                f"User     : {username}\n"
                f"IP       : {ip}\n"
                f"Status   : {status}")
            self.log_message(f"ALERT → Night login: {username} | {ip} | {timestamp}")

    def parse_log_line(self, line):
        # Common patterns for logs
        patterns = [
            # timestamp username ip success/failed
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+.*?(?:user|username|login):\s*(\S+).*?(?:from|ip|IP):\s*(\S+).*?(success|failed|failure|denied)',
            # sshd style
            r'(\S+\s+\d+\s+\d{2}:\d{2}:\d{2}).*?sshd.*?(\S+)\s+from\s+(\S+)',
            # simple timestamp + user + ip
            r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}).*?(\w+)\s+.*?(?:from|IP)\s*[:=]?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        ]

        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                groups = match.groups()
                if len(groups) >= 3:
                    ts = groups[0].strip()
                    user = groups[1].strip() if len(groups) > 1 else "unknown"
                    ip = groups[2].strip() if len(groups) > 2 else "unknown"
                    status = "✅ SUCCESS" if "success" in line.lower() else "❌ FAILED"
                    return ts, user, ip, status
        return None

    def load_log_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log Files", "*.log *.txt"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            self.log_message(f"Loading file: {file_path} ({len(lines)} lines)")

            night_count = 0
            parsed_count = 0

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                result = self.parse_log_line(line)
                if result:
                    timestamp, username, ip, status = result
                    parsed_count += 1
                    if self.is_night_time(timestamp):
                        night_count += 1
                    self.add_attempt(timestamp, username, ip, status)

            self.log_message(f"Parsing complete: {parsed_count} login attempts found, {night_count} night-time attempts")

            if night_count > 0:
                messagebox.showinfo("Scan Complete", 
                    f"Log file analysis finished!\n\n"
                    f"Total logins parsed : {parsed_count}\n"
                    f"Night-time logins   : {night_count} ⚠️")
            else:
                self.log_message("No night-time login attempts found in this file.")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file:\n{str(e)}")

    def simulate_login(self):
        now = datetime.now()
        if random.random() < 0.35:   # Chance to simulate night time
            hour = random.randint(0, 5)
            test_time = now.replace(hour=hour, minute=random.randint(0,59), second=random.randint(0,59))
        else:
            test_time = now

        timestamp = test_time.strftime("%Y-%m-%d %H:%M:%S")
        username = random.choice(["admin", "john", "sarah", "root", "user01", "backup"])
        ip = f"192.168.{random.randint(10,200)}.{random.randint(1,254)}"
        status = "✅ SUCCESS" if random.random() > 0.3 else "❌ FAILED"

        self.add_attempt(timestamp, username, ip, status)

    def add_manual_attempt(self):
        # (Same as previous version - kept for convenience)
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Manual Login Attempt")
        dialog.geometry("420x320")

        tk.Label(dialog, text="Timestamp (e.g. 2026-04-03 03:45:22)").pack(pady=5)
        time_entry = tk.Entry(dialog, width=35)
        time_entry.insert(0, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        time_entry.pack(pady=5)

        tk.Label(dialog, text="Username").pack(pady=5)
        user_entry = tk.Entry(dialog, width=35)
        user_entry.insert(0, "testuser")
        user_entry.pack(pady=5)

        tk.Label(dialog, text="IP Address").pack(pady=5)
        ip_entry = tk.Entry(dialog, width=35)
        ip_entry.insert(0, "172.16.5.33")
        ip_entry.pack(pady=5)

        success_var = tk.BooleanVar(value=True)
        tk.Checkbutton(dialog, text="Successful Login", variable=success_var).pack(pady=10)

        def submit():
            ts = time_entry.get().strip()
            user = user_entry.get().strip()
            ip = ip_entry.get().strip()
            status = "✅ SUCCESS" if success_var.get() else "❌ FAILED"

            if ts and user and ip:
                self.add_attempt(ts, user, ip, status)
                dialog.destroy()
            else:
                messagebox.showerror("Error", "Please fill all fields")

        tk.Button(dialog, text="Add Attempt", command=submit, bg="#4CAF50", fg="white", width=15).pack(pady=15)

    def clear_attempts(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.attempts.clear()
        self.alert_label.config(text="No alerts yet", fg="green", bg="#f0f0f0")
        self.log_text.configure(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state="disabled")

# ====================== RUN THE TOOL ======================
if __name__ == "__main__":
    root = tk.Tk()
    app = TimeBasedLoginAlertTool(root)
    root.mainloop()

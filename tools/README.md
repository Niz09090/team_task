## Task 4: Time-Based Alert Tool

**Description**  
This interactive GUI tool detects login attempts that occur between **00:00 and 06:00** and immediately generates a security alert for unusual behavior (e.g., possible brute-force attacks during off-hours).

**Features**
- Clean, modern Tkinter GUI
- Import any CSV login log file
- Real-time table view of all logs
- Automatic timestamp parsing (supports multiple formats)
- Night-time detection logic (00:00–05:59)
- Clear, colored alerts with details and recommendations
- One-click clear/reset functionality

**How to Run**

python time_based_alert_tool.py


## Task 6: Session Tracking System

**Description**  
This tool tracks user sessions by intelligently pairing **Login** and **Logout** events. It calculates the exact duration of each session and automatically detects abnormal behavior:
- Sessions shorter than **5 minutes** (too short)
- Sessions longer than **8 hours** (too long)

**Key Features**
- Full interactive GUI built with Tkinter
- Automatic session pairing per user
- Precise duration calculation (hours, minutes, seconds)
- Color-coded abnormal session highlighting
- Clear security alerts with recommendations
- Supports multiple timestamp formats

**CSV Format Required**
```csv
timestamp,username,event,ip
2026-04-03 09:15:22,john.doe,login,192.168.1.45
2026-04-03 17:45:10,john.doe,logout,192.168.1.45

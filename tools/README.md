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
```bash
python time_based_alert_tool.py

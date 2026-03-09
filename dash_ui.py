import os
import re
import pandas as pd
import numpy as np
import psutil
import dash
from dash import dcc, html, Input, Output, dash_table
import plotly.express as px
import plotly.graph_objects as go
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from datetime import datetime, timedelta
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

# --------------------------------------------------
# DASH APP
# --------------------------------------------------
app = dash.Dash(__name__)
server = app.server
app.title = "SOC Ransomware Detection Dashboard"

# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# Create necessary directories
os.makedirs(os.path.join(PROJECT_ROOT, "monitoring", "logs"), exist_ok=True)
os.makedirs(os.path.join(PROJECT_ROOT, "data"), exist_ok=True)
os.makedirs(os.path.join(PROJECT_ROOT, "models"), exist_ok=True)

SYSTEM_LOG = os.path.join(PROJECT_ROOT, "monitoring/logs/system.log")
FILE_LOG = os.path.join(PROJECT_ROOT, "monitoring/logs/file_system.log")
PROCESS_LOG = os.path.join(PROJECT_ROOT, "monitoring/logs/process_system.log")
NETWORK_CSV = os.path.join(PROJECT_ROOT, "data/network_features.csv")
MODEL_FILE = os.path.join(PROJECT_ROOT, "models/ml_model.pkl")
SCALER_FILE = os.path.join(PROJECT_ROOT, "models/scaler.pkl")

# --------------------------------------------------
# CORRELATOR ENGINE
# --------------------------------------------------
class CorrelatorEngine:
    """Correlates alerts from different sources to identify ransomware patterns"""
    
    def __init__(self):
        self.alert_history = []
        self.correlation_window = timedelta(minutes=5)
        
    def correlate(self, file_alerts, process_alerts, network_alerts):
        """Correlate alerts from different sources"""
        
        # Combine all alerts with timestamps
        all_alerts = []
        all_alerts.extend([(datetime.now(), 'file', a) for a in file_alerts])
        all_alerts.extend([(datetime.now(), 'process', a) for a in process_alerts])
        all_alerts.extend([(datetime.now(), 'network', a) for a in network_alerts])
        
        # Add to history
        self.alert_history.extend(all_alerts)
        
        # Clean old alerts
        cutoff = datetime.now() - self.correlation_window
        self.alert_history = [(ts, src, alert) for ts, src, alert in self.alert_history 
                             if ts > cutoff]
        
        # Count alerts by source in current window
        file_count = sum(1 for _, src, _ in self.alert_history if src == 'file')
        process_count = sum(1 for _, src, _ in self.alert_history if src == 'process')
        network_count = sum(1 for _, src, _ in self.alert_history if src == 'network')
        
        # Determine threat level based on correlation
        total_sources = sum(1 for count in [file_count, process_count, network_count] if count > 0)
        
        if total_sources >= 3 and (file_count > 5 or process_count > 3):
            return "CRITICAL", "Ransomware pattern detected across all vectors"
        elif total_sources >= 2:
            return "HIGH", "Multiple suspicious indicators detected"
        elif total_sources >= 1:
            return "MEDIUM", "Suspicious activity detected"
        else:
            return "LOW", "Normal activity"

# Initialize correlator
correlator = CorrelatorEngine()

# --------------------------------------------------
# LOG READER WITH ERROR HANDLING
# --------------------------------------------------
def read_log(path, tail=1000):
    """Read log files safely"""
    if not os.path.exists(path):
        print(f"Warning: Log file not found: {path}")
        return pd.DataFrame(columns=["Timestamp", "Source", "Event", "Details"])

    rows = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[-tail:]  # Read last tail lines
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                parts = line.split(maxsplit=4)
                
                if len(parts) >= 4:
                    # Handle timestamp format
                    timestamp = parts[0]
                    if len(parts) > 1 and ':' in parts[1]:  # If second part looks like time
                        timestamp = f"{parts[0]} {parts[1]}"
                        source_idx = 2
                        event_idx = 3
                        details_idx = 4
                    else:
                        source_idx = 1
                        event_idx = 2
                        details_idx = 3
                    
                    rows.append({
                        "Timestamp": timestamp,
                        "Source": parts[source_idx] if len(parts) > source_idx else "Unknown",
                        "Event": parts[event_idx] if len(parts) > event_idx else "Unknown",
                        "Details": parts[details_idx] if len(parts) > details_idx else ""
                    })
    except Exception as e:
        print(f"Error reading {path}: {e}")
    
    df = pd.DataFrame(rows)
    if df.empty:
        return pd.DataFrame(columns=["Timestamp", "Source", "Event", "Details"])
    return df


# --------------------------------------------------
# LOAD LOGS
# --------------------------------------------------
def load_logs():
    """Load all log files"""
    print(f"Reading system log: {SYSTEM_LOG}")
    system_df = read_log(SYSTEM_LOG)
    print(f"System log entries: {len(system_df)}")
    
    print(f"Reading file log: {FILE_LOG}")
    file_df = read_log(FILE_LOG)
    print(f"File log entries: {len(file_df)}")
    
    print(f"Reading process log: {PROCESS_LOG}")
    process_df = read_log(PROCESS_LOG)
    print(f"Process log entries: {len(process_df)}")
    
    return system_df, file_df, process_df


# --------------------------------------------------
# NETWORK DATA LOADING
# --------------------------------------------------
def load_network():
    """Load network features"""
    if not os.path.exists(NETWORK_CSV):
        print(f"Warning: Network data not found: {NETWORK_CSV}")
        return pd.DataFrame(columns=[
            "Source IP", "Packet Count", "Bytes Sent", "Protocols Used"
        ])

    try:
        df = pd.read_csv(NETWORK_CSV)
        df.columns = [c.strip() for c in df.columns]
        
        # Ensure numeric columns are properly typed
        numeric_cols = df.select_dtypes(include=['int64', 'float64']).columns
        for col in numeric_cols:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
            
        print(f"Network data entries: {len(df)}")
        return df
    except Exception as e:
        print(f"Error loading network data: {e}")
        return pd.DataFrame(columns=[
            "Source IP", "Packet Count", "Bytes Sent", "Protocols Used"
        ])


# --------------------------------------------------
# ENHANCED ML MODEL TRAINING (USES ALL LOGS)
# --------------------------------------------------
def extract_features_from_logs(system_df, file_df, process_df, network_df):
    """Extract numerical features from all log sources"""
    features = []
    
    # File system features
    if not file_df.empty:
        # Count of file operations by type
        file_ops = {
            'create': len(file_df[file_df['Event'].str.contains('CREATE|create', na=False)]),
            'modify': len(file_df[file_df['Event'].str.contains('MODIFY|modify|WRITE|write', na=False)]),
            'delete': len(file_df[file_df['Event'].str.contains('DELETE|delete', na=False)]),
            'rename': len(file_df[file_df['Event'].str.contains('RENAME|rename', na=False)]),
        }
        
        # Ransomware extensions detected
        ransomware_ext = ['.locked', '.encrypted', '.crypt', '.enc', '.ryk', '.conti', '.wanna']
        encrypted_count = 0
        for ext in ransomware_ext:
            encrypted_count += len(file_df[file_df['Details'].str.contains(ext, case=False, na=False)])
        
        features.extend([
            file_ops['create'],
            file_ops['modify'],
            file_ops['delete'],
            file_ops['rename'],
            encrypted_count
        ])
    else:
        features.extend([0, 0, 0, 0, 0])
    
    # Process features
    if not process_df.empty:
        suspicious_cmds = ['vssadmin', 'wmic', 'bcdedit', 'powershell', 'cmd.exe', 
                          'cipher', 'icacls', 'wbadmin', 'taskkill']
        suspicious_count = 0
        for cmd in suspicious_cmds:
            suspicious_count += len(process_df[process_df['Details'].str.contains(cmd, case=False, na=False)])
        
        # Process start events
        process_starts = len(process_df[process_df['Event'].str.contains('START|start', na=False)])
        
        features.extend([process_starts, suspicious_count])
    else:
        features.extend([0, 0])
    
    # Network features
    if not network_df.empty and 'Packet Count' in network_df.columns:
        total_packets = network_df['Packet Count'].sum() if 'Packet Count' in network_df.columns else 0
        avg_packet_size = network_df['Bytes Sent'].mean() if 'Bytes Sent' in network_df.columns else 0
        unique_ips = network_df['Source IP'].nunique() if 'Source IP' in network_df.columns else 0
        
        features.extend([total_packets, avg_packet_size, unique_ips])
    else:
        features.extend([0, 0, 0])
    
    return features


def train_model():
    """Train Isolation Forest model on all log sources"""
    print("Loading logs for training...")
    system_df, file_df, process_df = load_logs()
    network_df = load_network()
    
    # Extract features
    features = extract_features_from_logs(system_df, file_df, process_df, network_df)
    
    # Create feature matrix (need multiple samples, so create rolling windows)
    X = []
    for i in range(max(1, len(file_df) // 10)):
        X.append([f + np.random.normal(0, 1) for f in features])  # Add small noise for variety
    
    X = np.array(X)
    
    if len(X) < 10:
        # Create synthetic variations if not enough data
        for i in range(10):
            X = np.vstack([X, features + np.random.normal(0, 5, len(features))])
    
    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train Isolation Forest
    model = IsolationForest(
        contamination=0.1,
        random_state=42,
        n_estimators=100,
        bootstrap=False
    )
    
    model.fit(X_scaled)
    
    # Save model and scaler
    joblib.dump(model, MODEL_FILE)
    joblib.dump(scaler, SCALER_FILE)
    
    # Calculate expected anomaly count
    predictions = model.predict(X_scaled)
    n_anomalies = sum(predictions == -1)
    
    return f"ML Model trained on all logs! Detected {n_anomalies} anomalous patterns in training data."


def predict_anomaly(system_df, file_df, process_df, network_df):
    """Predict anomalies using trained model"""
    if not os.path.exists(MODEL_FILE) or not os.path.exists(SCALER_FILE):
        return 0  # No model, return normal score
    
    try:
        model = joblib.load(MODEL_FILE)
        scaler = joblib.load(SCALER_FILE)
        
        # Extract current features
        features = extract_features_from_logs(system_df, file_df, process_df, network_df)
        features = np.array(features).reshape(1, -1)
        
        # Scale features
        features_scaled = scaler.transform(features)
        
        # Predict
        prediction = model.predict(features_scaled)[0]
        score = model.decision_function(features_scaled)[0]
        
        # Return anomaly score (negative = anomalous)
        return score
        
    except Exception as e:
        print(f"Error in anomaly prediction: {e}")
        return 0


# --------------------------------------------------
# NETWORK ANALYTICS
# --------------------------------------------------
def top_ips(df):
    """Get top IPs by packet count"""
    if df.empty or "Source IP" not in df.columns:
        return pd.DataFrame(columns=["Source IP", "Packet Count"])

    if "Packet Count" in df.columns:
        return (
            df.groupby("Source IP")["Packet Count"]
            .sum()
            .reset_index()
            .sort_values("Packet Count", ascending=False)
            .head(10)
        )
    else:
        return pd.DataFrame(columns=["Source IP", "Packet Count"])


def protocol_stats(df):
    """Get protocol distribution"""
    if df.empty or "Protocols Used" not in df.columns:
        return pd.DataFrame(columns=["Protocol", "Count"])

    protocols = []
    for p in df["Protocols Used"].dropna():
        if isinstance(p, str):
            protocols.extend(p.split(","))

    if not protocols:
        return pd.DataFrame(columns=["Protocol", "Count"])

    proto_df = pd.DataFrame(protocols, columns=["Protocol"])
    return proto_df.value_counts().reset_index(name="Count")


# --------------------------------------------------
# ENHANCED RANSOMWARE DETECTION ENGINE
# --------------------------------------------------
def detect_ransomware(system_df, file_df, process_df, network_df):
    """Comprehensive ransomware detection using all log sources"""
    
    alerts = []
    risk_score = 0
    
    # Ransomware indicators
    ransomware_ext = [".locked", ".encrypted", ".crypt", ".enc", ".ryk", ".conti", ".wanna", ".cerber"]
    suspicious_cmds = [
        "vssadmin delete shadows", "wmic shadowcopy", "bcdedit",
        "powershell -enc", "cipher /w", "icacls", "wbadmin delete",
        "net stop", "taskkill", "reg delete", "sc delete"
    ]
    
    # FILE SYSTEM ANALYSIS
    if not file_df.empty and 'Details' in file_df.columns:
        # File encryption detection
        encrypted = file_df[
            file_df["Details"].astype(str).str.contains(
                "|".join(ransomware_ext),
                case=False,
                na=False
            )
        ]
        
        if len(encrypted) > 3:
            sample_files = encrypted['Details'].iloc[:3].tolist()
            alerts.append({
                "Threat": "[CRITICAL] File Encryption Detected",
                "Severity": "Critical",
                "Source": "File System",
                "Details": f"{len(encrypted)} encrypted files: {', '.join(sample_files)}",
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            risk_score += 40
        
        # Mass file modification
        if 'Event' in file_df.columns:
            mods = file_df[
                file_df["Event"].astype(str).str.contains(
                    "modify|rename|write|delete",
                    case=False,
                    na=False
                )
            ]
            
            if len(mods) > 30:
                alerts.append({
                    "Threat": "[HIGH] Mass File Modification",
                    "Severity": "High",
                    "Source": "File System",
                    "Details": f"{len(mods)} file changes detected in recent logs",
                    "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                risk_score += 25
    
    # PROCESS ANALYSIS
    if not process_df.empty and 'Details' in process_df.columns:
        # Shadow copy deletion
        shadow = process_df[
            process_df["Details"].astype(str).str.contains(
                "vssadmin delete shadows|wmic shadowcopy delete",
                case=False,
                na=False
            )
        ]
        
        if not shadow.empty:
            alerts.append({
                "Threat": "[CRITICAL] Shadow Copy Deletion",
                "Severity": "Critical",
                "Source": "Process",
                "Details": f"Backup deletion detected: {shadow.iloc[0]['Details'][:100]}",
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            risk_score += 35
        
        # Suspicious commands
        for cmd in suspicious_cmds:
            cmd_hits = process_df[
                process_df["Details"].astype(str).str.contains(cmd, case=False, na=False)
            ]
            
            if len(cmd_hits) > 2:
                alerts.append({
                    "Threat": "[MEDIUM] Suspicious Command",
                    "Severity": "Medium",
                    "Source": "Process",
                    "Details": f"Command detected: {cmd} ({len(cmd_hits)} times)",
                    "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                risk_score += 15
                break  # Only add once per detection window
    
    # NETWORK ANALYSIS
    if not network_df.empty:
        # High packet rate detection
        if 'Packet Count' in network_df.columns:
            high_traffic = network_df[network_df['Packet Count'] > network_df['Packet Count'].quantile(0.95)]
            if not high_traffic.empty:
                alerts.append({
                    "Threat": "[HIGH] Unusual Network Traffic",
                    "Severity": "High",
                    "Source": "Network",
                    "Details": f"{len(high_traffic)} connections with abnormally high packet count",
                    "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                risk_score += 20
    
    # ML-BASED ANOMALY DETECTION
    ml_score = predict_anomaly(system_df, file_df, process_df, network_df)
    if ml_score < -0.3:  # Anomaly threshold
        alerts.append({
            "Threat": "[HIGH] ML Anomaly Detected",
            "Severity": "High",
            "Source": "ML Engine",
            "Details": f"Unusual system behavior pattern detected (score: {ml_score:.2f})",
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        risk_score += 25
    
    # CORRELATION ENGINE
    file_alerts = [a for a in alerts if a['Source'] == 'File System']
    process_alerts = [a for a in alerts if a['Source'] == 'Process']
    network_alerts = [a for a in alerts if a['Source'] == 'Network']
    
    corr_severity, corr_msg = correlator.correlate(file_alerts, process_alerts, network_alerts)
    
    if corr_severity == "CRITICAL":
        alerts.insert(0, {
            "Threat": "[CORRELATOR] Ransomware Pattern Detected",
            "Severity": "Critical",
            "Source": "Correlator",
            "Details": corr_msg,
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        risk_score = min(risk_score + 30, 100)
    elif corr_severity == "HIGH":
        alerts.insert(0, {
            "Threat": "[CORRELATOR] Multiple Threats Detected",
            "Severity": "High",
            "Source": "Correlator",
            "Details": corr_msg,
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        risk_score = min(risk_score + 15, 100)
    
    # Cap risk score
    risk_score = min(risk_score, 100)
    
    return alerts, risk_score


# --------------------------------------------------
# UI STYLE
# --------------------------------------------------
CARD = {
    "background": "#1f2c56",
    "color": "white",
    "padding": "15px",
    "borderRadius": "10px",
    "textAlign": "center",
    "width": "22%",
    "boxShadow": "0 4px 6px rgba(0, 0, 0, 0.1)"
}

HEADER_STYLE = {
    "textAlign": "center",
    "color": "#1f2c56",
    "marginBottom": "30px",
    "marginTop": "20px"
}


# --------------------------------------------------
# DASHBOARD LAYOUT
# --------------------------------------------------
app.layout = html.Div([

    html.H1(
        "SOC Ransomware Detection Dashboard",
        style=HEADER_STYLE
    ),
    
    html.H4(
        "Real-time monitoring from system logs | ML-powered detection | Correlator engine",
        style={"textAlign": "center", "color": "#666", "marginBottom": "30px"}
    ),

    # System stats cards
    html.Div([

        html.Div([html.H4("CPU"), html.H2(id="cpu")], style=CARD),
        html.Div([html.H4("Memory"), html.H2(id="mem")], style=CARD),
        html.Div([html.H4("Disk"), html.H2(id="disk")], style=CARD),
        html.Div([html.H4("Risk Score"), html.H2(id="risk")], style=CARD),

    ], style={
        "display": "flex",
        "gap": "20px",
        "justifyContent": "space-around",
        "marginBottom": "30px"
    }),

    # Charts row
    html.Div([
        dcc.Graph(id="top_ips"),
        dcc.Graph(id="protocol_chart"),
    ], style={"display": "flex", "gap": "20px"}),

    # Alerts section
    html.H3("Active Security Alerts", style={"marginTop": "30px"}),

    dash_table.DataTable(
        id="alerts",
        page_size=10,
        style_table={"overflowX": "auto"},
        style_header={
            "backgroundColor": "#1f2c56",
            "color": "white",
            "fontWeight": "bold",
            "textAlign": "center"
        },
        style_data_conditional=[
            {"if": {"filter_query": "{Severity} = 'Critical'"},
             "backgroundColor": "#ff4444", "color": "white"},
            {"if": {"filter_query": "{Severity} = 'High'"},
             "backgroundColor": "#ff8800", "color": "white"},
            {"if": {"filter_query": "{Severity} = 'Medium'"},
             "backgroundColor": "#ffbb33", "color": "black"},
            {"if": {"filter_query": '{Source} contains "Correlator"'},
             "backgroundColor": "#1a003d", "color": "#c084fc", "fontWeight": "bold"},
        ],
        style_cell={
            "textAlign": "left",
            "padding": "10px",
            "minWidth": "100px"
        }
    ),

    # Log tables
    html.H3("System Logs", style={"marginTop": "30px"}),
    dash_table.DataTable(id="system_logs", page_size=10),

    html.H3("File System Logs"),
    dash_table.DataTable(id="file_logs", page_size=10),

    html.H3("Process Logs"),
    dash_table.DataTable(id="process_logs", page_size=10),

    # ML Training button
    html.Div([
        html.Button("Train ML Model on All Logs", id="train", n_clicks=0,
                   style={
                       "backgroundColor": "#1f2c56",
                       "color": "white",
                       "padding": "12px 24px",
                       "border": "none",
                       "borderRadius": "5px",
                       "fontSize": "16px",
                       "cursor": "pointer",
                       "marginTop": "20px",
                       "marginRight": "20px"
                   }),
        html.Div(id="ml_status", style={
            "display": "inline-block",
            "padding": "12px",
            "backgroundColor": "#f8f9fa",
            "borderRadius": "5px",
            "minWidth": "300px",
            "marginTop": "20px"
        })
    ], style={"display": "flex", "alignItems": "center"}),

    dcc.Interval(id="refresh", interval=5000, n_intervals=0)

])


# --------------------------------------------------
# DASHBOARD UPDATE
# --------------------------------------------------
@app.callback(
    Output("cpu", "children"),
    Output("mem", "children"),
    Output("disk", "children"),
    Output("risk", "children"),
    Output("top_ips", "figure"),
    Output("protocol_chart", "figure"),
    Output("alerts", "data"),
    Output("alerts", "columns"),
    Output("system_logs", "data"),
    Output("system_logs", "columns"),
    Output("file_logs", "data"),
    Output("file_logs", "columns"),
    Output("process_logs", "data"),
    Output("process_logs", "columns"),
    Input("refresh", "n_intervals")
)
def update_dashboard(n):

    # System metrics
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage(os.getcwd()).percent

    # Load logs
    print("\n" + "="*50)
    print(f"Updating dashboard at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    system_df, file_df, process_df = load_logs()
    net_df = load_network()

    # Detect threats
    alerts, risk = detect_ransomware(system_df, file_df, process_df, net_df)

    # Network analytics
    topip = top_ips(net_df)
    if not topip.empty:
        fig1 = px.bar(
            topip,
            x="Source IP",
            y="Packet Count",
            title="Top Network IPs by Traffic",
            color="Packet Count",
            color_continuous_scale="Viridis"
        )
    else:
        fig1 = px.bar(title="No Network Data Available")

    proto = protocol_stats(net_df)
    if not proto.empty:
        proto.columns = ["Protocol", "Count"]
        fig2 = px.pie(
            proto,
            names="Protocol",
            values="Count",
            title="Protocol Distribution",
            color_discrete_sequence=px.colors.qualitative.Set3
        )
    else:
        fig2 = px.pie(title="No Protocol Data Available")

    # Configure alert columns
    alert_cols = [
        {"name": "Timestamp", "id": "Timestamp"},
        {"name": "Threat", "id": "Threat"},
        {"name": "Severity", "id": "Severity"},
        {"name": "Source", "id": "Source"},
        {"name": "Details", "id": "Details"}
    ] if alerts else []

    # Prepare log data
    sys_data = system_df.tail(20).to_dict("records") if not system_df.empty else []
    file_data = file_df.tail(20).to_dict("records") if not file_df.empty else []
    proc_data = process_df.tail(20).to_dict("records") if not process_df.empty else []

    sys_cols = [{"name": c, "id": c} for c in system_df.columns] if not system_df.empty else []
    file_cols = [{"name": c, "id": c} for c in file_df.columns] if not file_df.empty else []
    proc_cols = [{"name": c, "id": c} for c in process_df.columns] if not process_df.empty else []

    print(f"Alerts detected: {len(alerts)}, Risk score: {risk}")
    print("="*50)

    return (
        f"{cpu}%",
        f"{mem}%",
        f"{disk}%",
        f"{risk}%",
        fig1,
        fig2,
        alerts,
        alert_cols,
        sys_data,
        sys_cols,
        file_data,
        file_cols,
        proc_data,
        proc_cols
    )


# --------------------------------------------------
# TRAIN MODEL
# --------------------------------------------------
@app.callback(
    Output("ml_status", "children"),
    Input("train", "n_clicks"),
    prevent_initial_call=True
)
def train_callback(n_clicks):
    if n_clicks and n_clicks > 0:
        result = train_model()
        return result
    return "Click to train ML model on all log sources"


# --------------------------------------------------
# RUN SERVER
# --------------------------------------------------
if __name__ == "__main__":
    print("="*70)
    print("STARTING SOC Ransomware Detection Dashboard")
    print("="*70)
    print(f"Dashboard URL: http://127.0.0.1:8050")
    print(f"Project Root: {PROJECT_ROOT}")
    print(f"Reading logs from:")
    print(f"  - System Log: {SYSTEM_LOG}")
    print(f"  - File Log: {FILE_LOG}")
    print(f"  - Process Log: {PROCESS_LOG}")
    print(f"  - Network Data: {NETWORK_CSV}")
    print("="*70)
    print("No admin privileges required")
    print("Dashboard reads existing log files only")
    print("ML Model trains on all log sources for comprehensive detection")
    print("Correlator engine combines alerts from multiple sources")
    print("="*70)
    
    app.run(debug=True, host="127.0.0.1", port=8050)
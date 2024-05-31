import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json

# Load the JSON data
data_path = '../data/eve.json'
with open(data_path, 'r') as file:
    data = json.load(file)

# Convert JSON to DataFrame
df = pd.json_normalize(data)

# Convert timestamp to datetime
df['timestamp'] = pd.to_datetime(df['timestamp'])

# Extract date for grouping
df['date'] = df['timestamp'].dt.date

# Preprocess data for graphs
alerts_over_time = df.groupby('date').size().reset_index(name='counts')
severity_distribution = df['alert.severity'].value_counts().reset_index()
severity_distribution.columns = ['severity', 'counts']
top_src_ips = df['src_ip'].value_counts().head(10).reset_index()
top_src_ips.columns = ['src_ip', 'counts']
protocol_distribution = df['proto'].value_counts().reset_index()
protocol_distribution.columns = ['protocol', 'counts']
top_alert_signatures = df['alert.signature'].value_counts().head(10).reset_index()
top_alert_signatures.columns = ['signature', 'counts']

# Create figures
fig = make_subplots(rows=3, cols=2,
                    specs=[[{"colspan": 2}, None],
                           [{'type': 'domain'}, {'type': 'xy'}],
                           [{'type': 'domain'}, {'type': 'xy'}]],
                    subplot_titles=("Alerts Over Time", "Alert Severity Distribution", 
                                    "Top Source IPs", "Protocol Distribution", "Top Alert Signatures"))

# Alerts Over Time
fig.add_trace(go.Scatter(x=alerts_over_time['date'], y=alerts_over_time['counts'], mode='lines+markers', name='Alerts Over Time'), row=1, col=1)

# Alert Severity Distribution
fig.add_trace(go.Pie(labels=severity_distribution['severity'], values=severity_distribution['counts'], name='Severity Distribution'), row=2, col=1)

# Top Source IPs
fig.add_trace(go.Bar(x=top_src_ips['src_ip'], y=top_src_ips['counts'], name='Top Source IPs'), row=2, col=2)

# Protocol Distribution
fig.add_trace(go.Pie(labels=protocol_distribution['protocol'], values=protocol_distribution['counts'], name='Protocol Distribution'), row=3, col=1)

fig.add_trace(go.Bar(x=top_alert_signatures['signature'], y=top_alert_signatures['counts'], name='Top Alert Signatures'), row=3, col=2)


fig.update_layout(template='plotly_dark', title_text='Network Security Alerts Dashboard', showlegend=True)


fig.write_html("../output/dashboard.html")


fig.show()

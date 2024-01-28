import dash
from dash import html, dcc
from dash_table import DataTable
import pandas as pd
from datetime import datetime

# Read log data from log.txt file
log_file_path = 'logs.txt'

# Read log data from the file into a DataFrame
columns = ['LogEntry']
df = pd.read_csv(log_file_path, names=columns)

# Extract information from the log entry
df[['Timestamp', 'IP', 'Request', 'Status']] = df['LogEntry'].str.extract(r'(\S+ \S+) (\S+) <Request \'(\S+)\' \[GET\]> (\S+)', expand=True)

# Convert the timestamp column to datetime format
df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%Y-%m-%d %H:%M:%S.%f', errors='coerce')

# Initialize the Dash app
app = dash.Dash(__name__)

# Define the layout of the dashboard
app.layout = html.Div([
    html.H1("Log Analysis Dashboard"),
    
    # Table displaying log entries
    html.Div([
        html.H3("Log Entries"),
        DataTable(
            id='log-table',
            columns=[{"name": col, "id": col} for col in df.columns],
            data=df.to_dict('records')
        )
    ]),

    # Pie chart for the distribution of blocked requests
    dcc.Graph(
        id='status-distribution',
        figure={
            'data': [
                {'labels': df['Status'].unique(), 'values': df['Status'].value_counts(), 'type': 'pie', 'name': 'Status Distribution'},
            ],
            'layout': {
                'title': 'Status Distribution'
            }
        }
    )
])

# Run the app
if __name__ == '__main__':
    app.run_server(debug=True)

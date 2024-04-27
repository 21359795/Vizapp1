import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objs as go
from scapy.layers.inet import TCP
from scapy.all import rdpcap

app = dash.Dash(__name__)
server = app.server
# Load initial data
packets = rdpcap('SIMULCRYPT.pcap')
packet_index = 0
max_packets_per_update = 100

initial_trace = go.Scatter(
    x=[packet.time for packet in packets[:max_packets_per_update]],
    y=[packet[TCP].dport for packet in packets[:max_packets_per_update] if packet.haslayer(TCP)],
    mode='lines',
    marker=dict(color='skyblue'),
    name='Destination Port'
)

initial_layout = go.Layout(
    xaxis=dict(title='Timestamp'),
    yaxis=dict(title='Destination Port'),
    title='Destination Port vs. Timestamp',
    showlegend=True
)

app.layout = html.Div([
    dcc.Graph(id='graph', figure={'data': [initial_trace], 'layout': initial_layout}),
    dcc.Interval(
        id='interval-component',
        interval=1000,  # in milliseconds
        n_intervals=0
    )
])

@app.callback(
    Output('graph', 'figure'),
    [Input('interval-component', 'n_intervals')]
)
def update_graph(n_intervals):
    global packet_index
    global packets

    # Determine the range of packets to process and plot
    start_index = packet_index
    end_index = min(packet_index + max_packets_per_update, len(packets))

    # Process packets within the range
    dest_ports = []
    timestamps = []
    for packet in packets[start_index:end_index]:
        if packet.haslayer(TCP):
            dest_ports.append(packet[TCP].dport)
            timestamps.append(packet.time)

    # Update the trace
    trace = go.Scatter(
        x=timestamps,
        y=dest_ports,
        mode='lines',
        marker=dict(color='skyblue'),
        name='Destination Port'
    )

    # Update packet index for next iteration
    packet_index = end_index

    # Check if reached the end of packet list, reset packet_index to 0
    if packet_index >= len(packets):
        packet_index = 0

    # Return updated figure
    return {'data': [trace], 'layout': initial_layout}

if __name__ == '__main__':
    app.run_server(debug=True)



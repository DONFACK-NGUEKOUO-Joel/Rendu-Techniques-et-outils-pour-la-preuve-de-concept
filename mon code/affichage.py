import pickle
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.express as px
import pandas as pd

#Pour le chemin
chemin = r"C:\ENS_Paris_Saclay\Cours_S_1\Techniques et outils pour la preuve de concept\mon code\modbus_flows"

with open(chemin, 'rb') as f:
    data = pickle.load(f)

# Créer un DataFrame pour les connexions
connections_data = []
for key, value in data.items():
    src_ip, src_port, dst_ip, dst_port = key
    connections_data.append({
        'source_ip': src_ip,
        'source_port': src_port,
        'dest_ip': dst_ip,
        'dest_port': dst_port,
        'connexion': f"{src_ip}:{src_port}→{dst_ip}:{dst_port}"
    })

df = pd.DataFrame(connections_data)

# Graphique interactif 1 : Network Graph
fig1 = go.Figure()

# Ajouter les arêtes
edge_x = []
edge_y = []
for _, row in df.iterrows():
    # Simuler des positions
    edge_x.extend([row['source_ip'], row['dest_ip'], None])
    edge_y.extend([row['source_port'], row['dest_port'], None])

fig1.add_trace(go.Scatter(
    x=edge_x, y=edge_y,
    line=dict(width=0.5, color='#888'),
    hoverinfo='none',
    mode='lines'))

# Ajouter les nœuds
fig1.add_trace(go.Scatter(
    x=df['source_ip'].tolist() + df['dest_ip'].tolist(),
    y=df['source_port'].tolist() + df['dest_port'].tolist(),
    mode='markers+text',
    text=df['source_ip'].tolist() + df['dest_ip'].tolist(),
    textposition="bottom center",
    marker=dict(
        size=10,
        color=['blue']*len(df) + ['red']*len(df),
        line_width=2)))

fig1.update_layout(
    title='Carte Interactive des Connexions Modbus',
    showlegend=False,
    hovermode='closest',
    xaxis=dict(showgrid=False, zeroline=False),
    yaxis=dict(showgrid=False, zeroline=False))

# Graphique interactif 
fig2 = px.bar(df, x='dest_ip', color='source_ip',
              title='Connexions par Destination',
              labels={'dest_ip': 'IP Destination', 'count': 'Nombre'},
              height=400)

# Graphique interactif 3 : Sunburst
fig3 = px.sunburst(df, path=['source_ip', 'dest_ip', 'dest_port'],
                   title='Hiérarchie des Connexions',
                   height=500)

# Afficher
fig1.show()
fig2.show()
fig3.show()

# Sauvegarder en HTML
fig1.write_html("network_graph.html")
fig2.write_html("connexions_bar.html")
fig3.write_html("sunburst.html")

print(" Graphiques interactifs sauvegardés en HTML !")
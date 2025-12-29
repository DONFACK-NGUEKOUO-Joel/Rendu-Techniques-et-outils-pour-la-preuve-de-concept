# Importation des bibliotheques
import numpy as np # bilbiotheque pour le calcul scientifique et manipulation de matrices
import matplotlib.pyplot as plt # bilbiotheque pour le graphiques et visualisation
from mpl_toolkits.mplot3d import Axes3D

# Lecture des données depuis le fichier texte 
fichier = "data.txt"  # On s'assure que data.txt est dans le même dossier que ce script
data = np.loadtxt(fichier) # On importe le fichier


# Vérification, on s'assure que les fichier est bien sur 3 colones
if data.shape[1] != 3:
    raise ValueError("Le fichier doit contenir 3 colonnes : x y z")

x = data[:, 0]
y = data[:, 1]
z = data[:, 2]

# Calcul du plan des moindres carrés 
# Modèle utilise : z = a*x + b*y + c
A = np.c_[x, y, np.ones(x.shape)]
coeffs, _, _, _ = np.linalg.lstsq(A, z, rcond=None)
a, b, c = coeffs

print("✅ Équation du plan des moindres carrés :")
print(f"z = {a:.4f} * x + {b:.4f} * y + {c:.4f}")  #Afficher l'equation du plan

# Visualisation
fig = plt.figure() # création d'une figure
ax = fig.add_subplot(111, projection='3d') # ajoute un subplot à la figure, avec projection en 3D

# Nuage de points
ax.scatter(x, y, z, color='black', label="Données") # trace du nuage de points 3D avec les coordonnées (x, y, z)

# Plan ajusté
x_grid, y_grid = np.meshgrid(
    np.linspace(min(x), max(x), 20),
    np.linspace(min(y), max(y), 20)
)
z_grid = a * x_grid + b * y_grid + c
ax.plot_surface(x_grid, y_grid, z_grid, alpha=0.5, color='blue')
# x_grid et y_grid sont deux matrices qui contiennent les coordonnées de la grille.

# Titres et labels
ax.set_xlabel("X") # Label axe des x
ax.set_ylabel("Y")  # Label axe des y
ax.set_zlabel("Z")  # Label axe des z
ax.set_title("Plan des moindres carrés") # label du titre du graphe
ax.legend()

plt.show()

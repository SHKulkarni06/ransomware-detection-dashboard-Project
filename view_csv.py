# view_csv.py
from tabulate import tabulate
import pandas as pd

# Load your CSV
df = pd.read_csv("data/network_features.csv")

# Print in nice table
print(tabulate(df, headers='keys', tablefmt='grid'))

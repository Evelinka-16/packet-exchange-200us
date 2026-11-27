import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

names = {'node0': 'user (node0)', 'node1': 'pc1 (node1)', 'node2': 'pc4 (node2)'}

dfs = []
for f, name in names.items():
    t = pd.read_csv(f'results/{f}.csv')
    t = t[(t['round'] >= 100) & (t['status'] == 0)].copy()
    t['node'] = name
    dfs.append(t)
df = pd.concat(dfs, ignore_index=True)

plt.figure(figsize=(10, 5))
sns.histplot(data=df, x='exchange_us', hue='node', bins=np.arange(0, 252, 2), element='step', alpha=0.4)
plt.axvline(200, color='red', linestyle='--')
plt.xlim(0, 250)
plt.xlabel('Задержка раунда (exchange_us), мкс')
plt.ylabel('Количество раундов')
plt.title('Распределение задержек обмена на трёх ПК')
plt.tight_layout()
plt.savefig('hist_all.png', dpi=200)

fig, axes = plt.subplots(3, 1, figsize=(10, 9), sharex=True)
for ax, t in zip(axes, dfs):
    x = t['exchange_us']
    ax.hist(x, bins=np.arange(0, 305, 5), color='steelblue', edgecolor='white')
    ax.axvline(200, color='red', linestyle='--')
    ax.set_yscale('log')
    ax.set_ylabel('Раундов')
    ax.set_title(f"{t['node'].iloc[0]}: среднее {x.mean():.1f} мкс, максимум {x.max():.1f} мкс, "
                 f"раундов от 200 мкс: {(x >= 200).sum()}", fontsize=11)
    ax.grid(axis='y', alpha=0.3)
axes[-1].set_xlabel('Задержка раунда (exchange_us), мкс')
axes[-1].set_xlim(0, 300)
plt.tight_layout()
plt.savefig('hist_by_pc.png', dpi=200)

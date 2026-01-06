import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
import os
from sklearn.metrics import roc_curve

# Ensure plots directory exists
PLOTS_DIR = 'plots'
os.makedirs(PLOTS_DIR, exist_ok=True)

def plot_roc_curves(models_probs, y_test, title="ROC Curves", filename="roc_curves.png"):
    """
    Plots ROC curves for multiple models and saves the figure.
    Style matched to fullcode.py logic.
    """
    plt.figure(figsize=(10, 8))
    
    # Calculate colors and labels based on fullcode.py style
    style_map = {
        'logistic_regression': {'color': 'orange', 'label': 'Logistic Regression'},
        'random_forest': {'color': 'yellow', 'label': 'Random Forest'},
        'knn': {'color': 'green', 'label': 'KNN'},
        'decision_tree': {'color': 'blue', 'label': 'Decision Tree'},
        'naive_bayes': {'color': 'red', 'label': 'Gaussian'}
    }
    
    text_y_offset = 0.21
    
    from sklearn.metrics import roc_auc_score
    
    for name, y_prob in models_probs.items():
        if y_prob is not None:
            fpr, tpr, _ = roc_curve(y_test, y_prob)
            auc = roc_auc_score(y_test, y_prob)
            
            style = style_map.get(name, {'color': 'blue', 'label': name})
            plt.plot(fpr, tpr, linestyle='--', color=style['color'], label=style['label'])
            
            if name in style_map:
                plt.text(0.6, text_y_offset, f"AUC {name[:3].upper()} = {auc:.4f}", 
                         ha='center', fontsize=10, weight='bold', color=str(style['color']))
                text_y_offset -= 0.05
            
    # Random guess line
    plt.plot([0, 1], [0, 1], linestyle='--', color='black')
    
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title(title)
    plt.legend(loc='best')
    plt.savefig(os.path.join(PLOTS_DIR, filename), dpi=500)
    plt.close()

def plot_feature_importance(model, feature_names, filename="feature_importance.png"):
    """
    Plots feature importance for tree-based models and saves the figure.
    """
    if hasattr(model, 'feature_importances_'):
        plt.figure(figsize=(10, 8))
        importances = model.feature_importances_
        sns.barplot(x=importances, y=feature_names)
        plt.title('Feature Importance')
        plt.savefig(os.path.join(PLOTS_DIR, filename))
        plt.close()

def plot_ip_distribution(all_ip_df, top_n=44, filename="ip_distribution.png"):
    """
    Plots the distribution of IP addresses and saves the figure.
    """
    g = all_ip_df.nlargest(columns="Count", n=top_n)
    plt.figure(figsize=(12, 15))
    ax = sns.barplot(data=g, x="Count", y="ip")
    ax.set(ylabel='IP Address')
    plt.title(f'Top {top_n} IP Address Frequencies')
    plt.savefig(os.path.join(PLOTS_DIR, filename))
    plt.close()

def plot_correlation_matrix(df, graph_width=20, title='Correlation Matrix', filename="correlation_matrix.png"):
    """
    Plots a correlation matrix and saves the figure.
    """
    df_numeric = df.select_dtypes(include=[np.number])
    df_numeric = df_numeric.dropna(axis=1, how='all')
    df_numeric = df_numeric[[col for col in df_numeric if df_numeric[col].nunique() > 1]]
    
    if df_numeric.shape[1] < 2:
        print('No correlation plots shown: The number of non-NaN or constant columns is less than 2')
        return
        
    corr = df_numeric.corr()
    plt.figure(num=None, figsize=(graph_width, graph_width), dpi=80, facecolor='w', edgecolor='k')
    corr_mat = plt.matshow(corr, fignum=1)
    plt.xticks(range(len(corr.columns)), corr.columns, rotation=90)
    plt.yticks(range(len(corr.columns)), corr.columns)
    plt.gca().xaxis.tick_bottom()
    plt.colorbar(corr_mat)
    plt.title(title, fontsize=15)
    plt.savefig(os.path.join(PLOTS_DIR, filename))
    plt.close()

def plot_scatter_matrix(df, plot_size=20, text_size=10, filename="scatter_matrix.png"):
    """
    Plots scatter and density plots and saves the figure.
    """
    df_numeric = df.select_dtypes(include=[np.number])
    df_numeric = df_numeric.dropna(axis=1)
    df_numeric = df_numeric[[col for col in df_numeric if df_numeric[col].nunique() > 1]]
    
    column_names = list(df_numeric)
    if len(column_names) > 10:
        column_names = column_names[:10]
        
    df_small = df_numeric[column_names]
    ax = pd.plotting.scatter_matrix(df_small, alpha=0.75, figsize=(plot_size, plot_size), diagonal='kde')
    corrs = df_small.corr().values
    
    # Correctly access axes in 2D array
    for i, j in zip(*np.triu_indices_from(ax, k=1)):
        cell = ax[i, j]
        cell.annotate('Corr. coef = %.3f' % corrs[i, j], (0.8, 0.2), 
                      xycoords='axes fraction', ha='center', va='center', size=text_size)
        
    plt.suptitle('Scatter and Density Plot')
    plt.savefig(os.path.join(PLOTS_DIR, filename))
    plt.close()

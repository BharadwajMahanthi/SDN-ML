import pandas as pd
import os
from src.data_processing import load_data, preprocess_sdn_data, split_data, get_ip_frequency
from src.models import get_models, train_model
from src.evaluation import evaluate_model, print_evaluation
from src.visualization import (
    plot_roc_curves, plot_feature_importance, 
    plot_ip_distribution, plot_correlation_matrix, 
    plot_scatter_matrix
)
from src.eda import comprehensive_eda

def run_pipeline(csv_path, dataset_name="SDN Data"):
    print(f"\n{'='*60}")
    print(f"ML Pipeline for: {dataset_name}")
    print(f"{'='*60}\n")

    # Step 1: Load Data
    print("Step 1: Loading data...")
    df = load_data(csv_path)
    if df is None:
        return

    # Step 2: Comprehensive Scientific EDA
    print("\nStep 2: Comprehensive Exploratory Data Analysis...")
    target_col = 'ABF' if 'ABF' in df.columns else 'label'
    eda_results = comprehensive_eda(df, target_col=target_col)

    # Step 3: Traditional EDA Visualizations
    print("\nStep 3: Generating EDA visualizations...")
    
    # IP Distribution (if applicable)
    if 'src' in df.columns:
        ip_df = get_ip_frequency(df)
        plot_ip_distribution(ip_df, filename=f"ip_distribution_{dataset_name.replace(' ', '_')}.png")
    
    # Correlation Matrix
    plot_correlation_matrix(df, title=f"Correlation Matrix: {dataset_name}", 
                             filename=f"corr_matrix_{dataset_name.replace(' ', '_')}.png")
    
    # Scatter Matrix
    plot_scatter_matrix(df, filename=f"scatter_matrix_{dataset_name.replace(' ', '_')}.png")

    # Step 4: Preprocessing
    print("\nStep 4: Preprocessing for ML...")
    if 'ABF' in df.columns:
        feature_set = ['Time', 'Source', 'Destination', 'Protocol', 'Length']
        label_col = 'ABF'
    else:
        feature_set = None
        label_col = 'label'
        
    X, y, feature_names = preprocess_sdn_data(df, feature_set=feature_set, label_column=label_col)
    X_train, X_test, y_train, y_test = split_data(X, y)

    # Step 5: Model Training and Evaluation
    print("\nStep 5: Model Training and Evaluation...")
    models = get_models()
    trained_models = {}
    metrics_log = {}
    models_probs = {}

    for name, model in models.items():
        print(f"Training {name}...")
        trained_model = train_model(model, X_train, y_train)
        trained_models[name] = trained_model
        
        metrics = evaluate_model(trained_model, X_test, y_test, X_train, y_train)
        metrics_log[name] = metrics
        models_probs[name] = metrics.get('y_prob')
        
        print_evaluation(name, metrics)

    # Step 6: Results Visualization
    print("\nStep 6: Visualizing Model Performance...")
    
    plot_roc_curves(models_probs, y_test, title=f"ROC Curves: {dataset_name}", 
                    filename=f"roc_curves_{dataset_name.replace(' ', '_')}.png")
    
    if "random_forest" in trained_models:
        rf_model = trained_models["random_forest"]
        if hasattr(rf_model, "estimators_"):
            rf_model = rf_model.estimators_[0]
        plot_feature_importance(rf_model, feature_names, 
                                filename=f"feat_importance_{dataset_name.replace(' ', '_')}.png")

    print(f"\n{dataset_name} Pipeline Complete!")
    print(f"  - EDA plots saved to: plots/eda/")
    print(f"  - Model plots saved to: plots/")

if __name__ == "__main__":
    # Process main dataset
    if os.path.exists("dataset_sdn.csv"):
        run_pipeline("dataset_sdn.csv", "Primary Dataset")
    
    # Process second dataset if exists
    if os.path.exists("Finalv3.csv"):
        run_pipeline("Finalv3.csv", "Secondary Dataset")

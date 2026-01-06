from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score, mean_squared_error

def evaluate_model(model, X_test, y_test, X_train=None, y_train=None):
    """
    Evaluates a model and returns a dictionary of metrics.
    """
    y_pred = model.predict(X_test)
    
    # Check if model has predict_proba for ROC AUC
    if hasattr(model, "predict_proba"):
        y_prob = model.predict_proba(X_test)[:, 1]
    elif hasattr(model, "decision_function"):
        y_prob = model.decision_function(X_test)
    else:
        y_prob = None
    
    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "report": classification_report(y_test, y_pred, output_dict=True),
        "conf_matrix": confusion_matrix(y_test, y_pred),
        "mse": mean_squared_error(y_test, y_pred),
        "y_prob": y_prob
    }
    
    if X_train is not None and y_train is not None:
        metrics["train_accuracy"] = accuracy_score(y_train, model.predict(X_train))
    
    if y_prob is not None:
        try:
            metrics["roc_auc"] = roc_auc_score(y_test, y_prob)
        except:
            pass
    
    return metrics

def print_evaluation(name, metrics):
    """
    Prints evaluation metrics in a readable format.
    """
    print(f"\nModel: {name}")
    if 'train_accuracy' in metrics:
        print(f"Train Accuracy: {metrics['train_accuracy']:.4f}")
    print(f"Test Accuracy: {metrics['accuracy']:.4f}")
    if 'roc_auc' in metrics:
        print(f"ROC AUC Score: {metrics['roc_auc']:.4f}")
    print(f"Mean Squared Error: {metrics['mse']:.4f}")
    print("Confusion Matrix:")
    print(metrics['conf_matrix'])

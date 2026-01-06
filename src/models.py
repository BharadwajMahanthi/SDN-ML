from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import LinearSVC
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.multiclass import OneVsRestClassifier

def get_models():
    """
    Returns a dictionary of initialized models with parameters from fullcode.py.
    """
    return {
        "logistic_regression": LogisticRegression(
            penalty='l2', solver='saga', max_iter=10000, random_state=42
        ),
        "random_forest": OneVsRestClassifier(
            RandomForestClassifier(
                criterion='gini', min_samples_split=10000, 
                min_samples_leaf=1000, max_leaf_nodes=10000,
                n_estimators=1000, random_state=1000, bootstrap=True, oob_score=True
            )
        ),
        "knn": KNeighborsClassifier(
            n_neighbors=4, weights='distance', p=2, metric='minkowski', leaf_size=40
        ),
        "decision_tree": DecisionTreeClassifier(
            criterion='gini', splitter='best', max_depth=None, min_samples_split=10000, 
            min_samples_leaf=1000, max_features=14, random_state=50, 
            class_weight='balanced', ccp_alpha=0.01
        ),
        "naive_bayes": GaussianNB(),
        "svm": make_pipeline(
            StandardScaler(), 
            LinearSVC(random_state=60, tol=1e-5, max_iter=20000)
        )
    }

def train_model(model, X_train, y_train):
    """
    Trains a given model.
    """
    model.fit(X_train, y_train)
    return model

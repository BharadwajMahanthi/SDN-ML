import pandas as pd
import numpy as np
import nltk
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OrdinalEncoder

def load_data(filepath):
    """
    Loads the SDN dataset from a CSV file.
    """
    df = pd.read_csv(filepath)
    return df

def preprocess_sdn_data(df, feature_set=None, label_column='label'):
    """
    Performs preprocessing on SDN datasets as per fullcode.py logic.
    - Handles missing values.
    - Extracts features and labels.
    - Applies OrdinalEncoding to selected features.
    - Correctly aligns feature names with column order in X.
    """
    # 1. Handle missing values
    df = df.copy().dropna()
    
    if feature_set is None:
        # Default feature set for primary dataset (dataset_sdn.csv)
        feature_set = [
            'dt', 'switch', 'src', 'dst', 'pktcount', 'bytecount', 'dur', 'dur_nsec', 'tot_dur', 
            'flows', 'packetins', 'pktperflow', 'byteperflow', 'pktrate', 'Pairflow', 
            'Protocol', 'port_no', 'tx_bytes', 'rx_bytes', 'tx_kbps', 'rx_kbps', 'tot_kbps'
        ]
    
    # 3. Label extraction
    y = df[label_column]
    
    # 4. Ordinal Encoding
    # Logic: The first feature in feature_set is treated as continuous, the rest are encoded.
    le = OrdinalEncoder()
    cont_feat = feature_set[0]
    encoded_feats = feature_set[1:]
    
    cat_encoded = le.fit_transform(df[encoded_feats])
    cont_data = df[cont_feat].to_numpy().reshape(-1, 1)
    
    # X columns order: [encoded_feats, cont_feat]
    X = np.append(cat_encoded, cont_data, axis=1)
    
    # Final feature names in matching order
    final_feature_names = encoded_feats + [cont_feat]
    
    return X, y, final_feature_names

def split_data(X, y, test_size=0.4, random_state=42):
    """
    Splits the data into training and testing sets.
    """
    return train_test_split(X, y, test_size=test_size, random_state=random_state)

def get_ip_frequency(df, column='src'):
    """
    Calculates the frequency distribution of IP addresses.
    """
    ip_list = [i.split(',') for i in df[column]]
    all_ip = [item for sublist in ip_list for item in sublist]
    freq_dist = nltk.FreqDist(all_ip)
    
    all_ip_df = pd.DataFrame({
        'ip': list(freq_dist.keys()),
        'Count': list(freq_dist.values())
    })
    
    return all_ip_df

"""
Comprehensive Exploratory Data Analysis Module
Implements the scientific EDA framework for SDN ML datasets
"""
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
import os

PLOTS_DIR = 'plots/eda'
os.makedirs(PLOTS_DIR, exist_ok=True)

class DataQualityReport:
    """Section 3: Data Quality Assessment"""
    
    @staticmethod
    def missing_data_analysis(df):
        """3.1 Missing Data Analysis"""
        missing = df.isnull().sum()
        missing_pct = (missing / len(df)) * 100
        
        report = pd.DataFrame({
            'Missing_Count': missing[missing > 0],
            'Percentage': missing_pct[missing > 0]
        }).sort_values('Percentage', ascending=False)
        
        print("\n=== MISSING DATA ANALYSIS ===")
        if len(report) == 0:
            print("✓ No missing values detected")
        else:
            print(report)
            print(f"\nMissingness Pattern: {'MCAR' if report['Percentage'].max() < 1 else 'Systematic'}")
        
        return report
    
    @staticmethod
    def duplicate_check(df):
        """3.2 Duplicate & Consistency Checks"""
        duplicates = df.duplicated().sum()
        print(f"\n=== DUPLICATE CHECK ===")
        print(f"Duplicate rows: {duplicates} ({100*duplicates/len(df):.2f}%)")
        return duplicates
    
    @staticmethod
    def validity_checks(df, numeric_cols):
        """3.3 Validity & Range Checks"""
        print("\n=== VALIDITY CHECKS ===")
        issues = []
        
        for col in numeric_cols:
            if col in df.columns:
                negatives = (df[col] < 0).sum()
                if negatives > 0 and col in ['pktcount', 'bytecount', 'dur']:
                    issues.append(f"{col}: {negatives} negative values (should be non-negative)")
        
        if issues:
            for issue in issues:
                print(f"⚠ {issue}")
        else:
            print("✓ All numeric values within expected ranges")
        
        return issues

class UnivariateAnalysis:
    """Section 4: Univariate Analysis"""
    
    @staticmethod
    def numeric_distribution(df, numeric_cols, save_plots=True):
        """4.1 Numeric Features Distribution"""
        print("\n=== NUMERIC DISTRIBUTION ANALYSIS ===")
        
        stats_summary = []
        for col in numeric_cols[:10]:  # Limit to first 10 for readability
            if col in df.columns:
                data = df[col].dropna()
                skew = stats.skew(data)
                kurt = stats.kurtosis(data)
                
                stats_summary.append({
                    'Feature': col,
                    'Mean': data.mean(),
                    'Median': data.median(),
                    'Std': data.std(),
                    'Skewness': skew,
                    'Kurtosis': kurt,
                    'Distribution': 'Normal' if abs(skew) < 0.5 else 'Skewed'
                })
        
        summary_df = pd.DataFrame(stats_summary)
        print(summary_df.to_string(index=False))
        
        if save_plots:
            fig, axes = plt.subplots(3, 3, figsize=(15, 12))
            for idx, col in enumerate(numeric_cols[:9]):
                if col in df.columns:
                    ax = axes[idx // 3, idx % 3]
                    df[col].hist(bins=50, ax=ax, edgecolor='black')
                    ax.set_title(f'{col}\nSkew: {stats.skew(df[col].dropna()):.2f}')
                    ax.set_xlabel(col)
            plt.tight_layout()
            plt.savefig(os.path.join(PLOTS_DIR, 'numeric_distributions.png'), dpi=300)
            plt.close()
        
        return summary_df
    
    @staticmethod
    def categorical_distribution(df, categorical_cols):
        """4.2 Categorical Features"""
        print("\n=== CATEGORICAL DISTRIBUTION ===")
        
        for col in categorical_cols:
            if col in df.columns:
                counts = df[col].value_counts()
                print(f"\n{col}:")
                print(f"  Unique values: {df[col].nunique()}")
                print(f"  Most common: {counts.index[0]} ({100*counts.iloc[0]/len(df):.1f}%)")
                if df[col].nunique() <= 10:
                    print(f"  Distribution:\n{counts.head(10)}")

class BivariateAnalysis:
    """Section 5: Bivariate Analysis"""
    
    @staticmethod
    def correlation_with_target(df, target_col='label', top_n=15):
        """5.1 Feature Correlation with Target"""
        print("\n=== CORRELATION WITH TARGET ===")
        
        numeric_df = df.select_dtypes(include=[np.number])
        if target_col in numeric_df.columns:
            corr = numeric_df.corr()[target_col].sort_values(ascending=False)
            print(corr.head(top_n))
            
            # Visualize
            plt.figure(figsize=(10, 8))
            corr.head(top_n).plot(kind='barh', color='steelblue')
            plt.title(f'Top {top_n} Features Correlated with {target_col}')
            plt.xlabel('Correlation Coefficient')
            plt.tight_layout()
            plt.savefig(os.path.join(PLOTS_DIR, 'target_correlation.png'), dpi=300)
            plt.close()
            
            return corr
        return None
    
    @staticmethod
    def multicollinearity_check(df, threshold=0.8):
        """Section 6: Multivariate - Collinearity Detection"""
        print("\n=== MULTICOLLINEARITY CHECK ===")
        
        numeric_df = df.select_dtypes(include=[np.number])
        corr_matrix = numeric_df.corr().abs()
        
        # Find highly correlated pairs
        upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
        high_corr = [(column, row, upper.loc[row, column]) 
                     for column in upper.columns 
                     for row in upper.index 
                     if upper.loc[row, column] > threshold]
        
        if high_corr:
            print(f"⚠ Found {len(high_corr)} highly correlated pairs (>{threshold}):")
            for col1, col2, corr_val in high_corr[:10]:
                print(f"  {col1} <-> {col2}: {corr_val:.3f}")
        else:
            print(f"✓ No severe multicollinearity detected (threshold={threshold})")
        
        return high_corr

class OutlierAnalysis:
    """Section 7: Outlier & Anomaly Analysis"""
    
    @staticmethod
    def detect_outliers_iqr(df, numeric_cols):
        """7.1 IQR-based Outlier Detection"""
        print("\n=== OUTLIER DETECTION (IQR Method) ===")
        
        outlier_summary = []
        for col in numeric_cols[:10]:
            if col in df.columns:
                Q1 = df[col].quantile(0.25)
                Q3 = df[col].quantile(0.75)
                IQR = Q3 - Q1
                lower = Q1 - 1.5 * IQR
                upper = Q3 + 1.5 * IQR
                
                outliers = df[(df[col] < lower) | (df[col] > upper)][col]
                outlier_pct = 100 * len(outliers) / len(df)
                
                outlier_summary.append({
                    'Feature': col,
                    'Outliers': len(outliers),
                    'Percentage': outlier_pct,
                    'Interpretation': 'Attack Signal' if col in ['pktcount', 'bytecount'] else 'Check'
                })
        
        summary_df = pd.DataFrame(outlier_summary)
        print(summary_df.to_string(index=False))
        
        return summary_df

class BiasAssessment:
    """Section 9: Bias & Representativeness"""
    
    @staticmethod
    def class_balance_check(df, target_col='label'):
        """9.3 Label Bias - Class Imbalance"""
        print("\n=== CLASS BALANCE ASSESSMENT ===")
        
        if target_col in df.columns:
            counts = df[target_col].value_counts()
            percentages = 100 * counts / len(df)
            
            print(f"Class Distribution:")
            for cls, cnt in counts.items():
                print(f"  Class {cls}: {cnt} ({percentages[cls]:.1f}%)")
            
            imbalance_ratio = counts.max() / counts.min()
            print(f"\nImbalance Ratio: {imbalance_ratio:.2f}:1")
            
            if imbalance_ratio > 3:
                print("⚠ Severe imbalance detected - consider resampling")
            elif imbalance_ratio > 1.5:
                print("⚠ Moderate imbalance - monitor model performance")
            else:
                print("✓ Well-balanced dataset")
            
            return counts

def comprehensive_eda(df, target_col='label', save_summary=True):
    """
    Execute comprehensive EDA following the scientific framework
    """
    print("\n" + "="*60)
    print("COMPREHENSIVE EXPLORATORY DATA ANALYSIS")
    print("="*60)
    
    print(f"\nDataset Shape: {df.shape[0]} rows × {df.shape[1]} columns")
    
    # Identify column types
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
    
    # Execute all EDA sections
    results = {}
    
    # Section 3: Data Quality
    results['missing'] = DataQualityReport.missing_data_analysis(df)
    results['duplicates'] = DataQualityReport.duplicate_check(df)
    results['validity'] = DataQualityReport.validity_checks(df, numeric_cols)
    
    # Section 4: Univariate
    results['numeric_dist'] = UnivariateAnalysis.numeric_distribution(df, numeric_cols)
    UnivariateAnalysis.categorical_distribution(df, categorical_cols)
    
    # Section 5 & 6: Bivariate/Multivariate
    results['target_corr'] = BivariateAnalysis.correlation_with_target(df, target_col)
    results['multicollinearity'] = BivariateAnalysis.multicollinearity_check(df)
    
    # Section 7: Outliers
    results['outliers'] = OutlierAnalysis.detect_outliers_iqr(df, numeric_cols)
    
    # Section 9: Bias
    results['class_balance'] = BiasAssessment.class_balance_check(df, target_col)
    
    print("\n" + "="*60)
    print("EDA COMPLETE - Plots saved to:", PLOTS_DIR)
    print("="*60 + "\n")
    
    return results

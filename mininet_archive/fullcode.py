# %%
!pip install scikit-learn==1.1.3 

# %%
import numpy as np
import pandas as pd
import nltk
import re
from mpl_toolkits.mplot3d import Axes3D
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
plt.rcParams["figure.figsize"] = (11, 5)
import seaborn as sns
from sklearn.model_selection import train_test_split
# Performance metric
from sklearn.feature_extraction.text import TfidfVectorizer, ENGLISH_STOP_WORDS
from sklearn. feature_extraction. text import CountVectorizer
from sklearn.metrics import f1_score
from sklearn.metrics import confusion_matrix,accuracy_score
from sklearn.metrics import classification_report
from sklearn.metrics import roc_curve
from sklearn.metrics import roc_auc_score
import ipaddress


# %% [markdown]
# For colab
# 

# %%
from google.colab import drive
drive.mount('/content/drive')

# %%
# Read Data 
df1 = pd.read_csv("/content/drive/MyDrive/dataset_sdn.csv")
df1

# %% [markdown]
# For jupyter or local
# 

# %%
# Read Data 
df1 = pd.read_csv("dataset_sdn.csv")
df1

# %%
df1.isna().any()

# %%
df1 = df1.dropna()

# %%
df1.dataframeName = 'Final.csv'

# %%
df1.isna().any()

# %%
ip=[]

for i in df1['src']:
    j=i.split(',')
    ip.append(j)

    

# %%
all_ip = sum(ip,[])
len(set(all_ip))

# %%
all_ip = nltk.FreqDist(all_ip) 
# create dataframe
all_ip_df = pd.DataFrame({'ip': list(all_ip.keys()), 
                              'Count': list(all_ip.values())})

# %%
#visualizing the genre data and the rate of their occurrence using seaborn library
g = all_ip_df.nlargest(columns="Count", n = 44) 
plt.figure(figsize=(12,15)) 
ax = sns.barplot(data=g, x= "Count", y = "ip") 
ax.set(ylabel = 'Count') 
plt.show()

# %%
y = df1['label']

# %%
df1.info()

# %%
# Correlation matrix
def plotCorrelationMatrix(df, graphWidth):
    filename = df.dataframeName
    df = df.dropna('columns') # drop columns with NaN
    df = df[[col for col in df if df[col].nunique() > 1]] # keep columns where there are more than 1 unique values
    if df.shape[1] < 2:
        print(f'No correlation plots shown: The number of non-NaN or constant columns ({df.shape[1]}) is less than 2')
        return
    corr = df.corr()
    plt.figure(num=None, figsize=(graphWidth, graphWidth), dpi=80, facecolor='w', edgecolor='k')
    corrMat = plt.matshow(corr, fignum = 1)
    plt.xticks(range(len(corr.columns)), corr.columns, rotation=90)
    plt.yticks(range(len(corr.columns)), corr.columns)
    plt.gca().xaxis.tick_bottom()
    plt.colorbar(corrMat)
    plt.title(f'Correlation Matrix for {filename}', fontsize=15)
    plt.show()
    

# %%
# Scatter and density plots
def plotScatterMatrix(df, plotSize, textSize):
    df = df.select_dtypes(include =[np.number]) # keep only numerical columns
    # Remove rows and columns that would lead to df being singular
    df = df.dropna('columns')
    df = df[[col for col in df if df[col].nunique() > 1]] # keep columns where there are more than 1 unique values
    columnNames = list(df)
    if len(columnNames) > 10: # reduce the number of columns for matrix inversion of kernel density plots
        columnNames = columnNames[:10]
    df = df[columnNames]
    ax = pd.plotting.scatter_matrix(df, alpha=0.75, figsize=[plotSize, plotSize], diagonal='kde')
    corrs = df.corr().values
    for i, j in zip(*plt.np.triu_indices_from(ax, k = 1)):
        ax[i, j].annotate('Corr. coef = %.3f' % corrs[i, j], (0.8, 0.2), xycoords='axes fraction', ha='center', va='center', size=textSize)
    plt.suptitle('Scatter and Density Plot')
    plt.show()

# %%
plotCorrelationMatrix(df1, 20)

# %%
plotScatterMatrix(df1, 20, 10)

# %%
feature_set = ['dt','switch','src','dst','pktcount','bytecount','dur','dur_nsec','tot_dur',
               'flows','packetins','pktperflow','byteperflow','pktrate','Pairflow','Protocol','port_no','tx_bytes','rx_bytes','tx_kbps','rx_kbps','tot_kbps']

# %%
from sklearn.preprocessing import OrdinalEncoder
from sklearn.preprocessing import OneHotEncoder
le = OrdinalEncoder()
le.fit(df1)
cat_encoded = le.fit_transform(df1[feature_set[1:]])
print(type(cat_encoded), cat_encoded.shape)
cont_data = df1[feature_set[0]].to_numpy().reshape(-1,1) 
print(type(cont_data), cont_data.shape)
x_data = np.append(cat_encoded, cont_data, axis=1)
print(x_data.shape)
y_labels = df1['label']


from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(x_data, y_labels, test_size=0.4, random_state=42)

# %%
x_data

# %% [markdown]
# ## MODEL-1

# %%
from sklearn import tree
from sklearn.linear_model import LogisticRegression
# Create a tree object
model1 =LogisticRegression(penalty='l2', dual=False, tol=0.0001, C=1.0, fit_intercept=True, intercept_scaling=1, class_weight=None, random_state=None, solver='saga', 
                               max_iter=10000, multi_class='auto', verbose=0, n_jobs=None, l1_ratio=None)
# Ask the tree to fit the data to the labels!  That's it!
model1 = model1.fit(X_train, y_train)

from sklearn.metrics import confusion_matrix
results = confusion_matrix(y_test, model1.predict(X_test))

# %%
from sklearn.metrics import accuracy_score
accuracy_score(y_test, model1.predict(X_test))

# %%
accuracy_score(y_train, model1.predict(X_train))

# %%
results.shape,X_train.shape

# %%
y_pred1  =  model1.predict(X_test)
y_pred1

# %%
cm = confusion_matrix(y_test, y_pred1)
cm

# %%
print(classification_report(y_test, y_pred1))

# %%
pred_prob1 = model1.predict_proba(X_test)
pred_prob1

# %%
y_test1=y_test

# %%
from sklearn.metrics import mean_squared_error
training_error = mean_squared_error(y_train,model1.predict(X_train))
training_error

# %%
testing_error = mean_squared_error(y_test,y_pred1)
testing_error

# %% [markdown]
# ## MODEL-2

# %%
from sklearn.ensemble import RandomForestClassifier
reg = RandomForestClassifier(criterion='gini',min_samples_split = 10000,min_samples_leaf = 1000,max_leaf_nodes = 10000,
                             n_estimators = 1000, random_state = 1000,bootstrap= True,oob_score=True)

# %%
X_train, X_test, y_train, y_test = train_test_split(x_data, y_labels , test_size=0.4, random_state=42)

# %%
from sklearn.multiclass import OneVsRestClassifier
model2= OneVsRestClassifier(reg)
model2 = model2.fit(X_train, y_train)

# %%
y_pred2  =  model2.predict(X_test)
y_pred2

# %%
accuracy_score(y_test,  model2.predict(X_test))

# %%
accuracy_score(y_train, model2.predict(X_train))

# %%
from sklearn.metrics import classification_report
print(classification_report(y_test, y_pred2))

# %%
cm = confusion_matrix(y_test, y_pred2)
cm

# %%
from sklearn.metrics import mean_squared_error
training_error = mean_squared_error(y_train,model2.predict(X_train))
training_error

# %%
testing_error = mean_squared_error(y_test,y_pred2)
testing_error

# %%
pred_prob2 = model2.predict_proba(X_test)

# %%
y_test2=y_test

# %% [markdown]
# ## MODEL-3

# %%
from sklearn.neighbors import KNeighborsClassifier
X_train, X_test, y_train, y_test = train_test_split(x_data,y_labels , test_size=0.4, random_state=42)

# %%
model3 = KNeighborsClassifier(n_neighbors=4,weights='distance',p=2, metric='minkowski',leaf_size=40)

# %%
model3 = model3.fit(X_train, y_train)

# %%
print(model3.predict(X_test))

# %%
y_pred3=model3.predict(X_test)
y_pred3

# %%
from numpy import unique
from numpy import where
# retrieve unique clusters
clusters = unique(y_pred3)
# create scatter plot for samples from each cluster
for cluster in clusters:
    row_ix = where(y_pred3 == cluster)
	# create scatter of these samples
    plt.scatter(X_test[row_ix, 0], X_test[row_ix, 1])
# show the plot
plt.show()

# %%
from sklearn.metrics import classification_report
print(classification_report(y_test, y_pred3))

# %%
accuracy_score(y_test, model3.predict(X_test))

# %%
accuracy_score(y_train, model3.predict(X_train))

# %%
cm = confusion_matrix(y_test, y_pred3)
cm

# %%
pred_prob3 = model3.predict_proba(X_test)

# %%
y_test3=y_test

# %%
from sklearn.metrics import mean_squared_error
training_error = mean_squared_error(y_train,model3.predict(X_train))
training_error

# %%
testing_error = mean_squared_error(y_test,y_pred3)
testing_error

# %% [markdown]
# ## MODEL-4

# %%
from sklearn.tree import DecisionTreeClassifier
from sklearn.cluster import OPTICS
# Binary Relevance

# %%
X_train, X_test, y_train, y_test = train_test_split(x_data,y_labels , test_size=0.4, random_state=42)

# %%
model4 = DecisionTreeClassifier(criterion='gini', splitter='best', max_depth=None, min_samples_split=10000, 
                              min_samples_leaf=1000, min_weight_fraction_leaf=0.0, max_features=14, random_state=50, max_leaf_nodes=None, 
                              min_impurity_decrease=0.0, class_weight='balanced', ccp_alpha=0.01)

# %%
model4=model4.fit(X_train, y_train)

# %%
y_pred4 = model4.predict(X_test)
y_pred4

# %%
accuracy_score(y_test, model4.predict(X_test))

# %%
accuracy_score(y_train, model4.predict(X_train))

# %%
print(classification_report(y_test, y_pred4))

# %%
pred_prob4 = model4.predict_proba(X_test)

# %%
y_test4=y_test

# %%
cm = confusion_matrix(y_test, y_pred4)
cm

# %%
from sklearn.metrics import mean_squared_error
training_error = mean_squared_error(y_train,model4.predict(X_train))
training_error

# %%
testing_error = mean_squared_error(y_test,y_pred4)
testing_error

# %% [markdown]
# ## MODEL-5

# %%
from sklearn.naive_bayes import GaussianNB

# %%
X_train, X_test, y_train, y_test = train_test_split(x_data,y_labels , test_size=0.4, random_state=42)

# %%
model5 = GaussianNB(priors=None, var_smoothing=1e-09)

# %%
model5=model5.fit(X_train, y_train)

# %%
y_pred5 = model5.predict(X_test)
y_pred5

# %%
accuracy_score(y_test, model5.predict(X_test))

# %%
accuracy_score(y_train, model5.predict(X_train))

# %%
print(classification_report(y_test, y_pred5))

# %%
pred_prob5 = model5.predict_proba(X_test)

# %%
y_test5=y_test

# %%
cm = confusion_matrix(y_test, y_pred5)
cm

# %%
from sklearn.metrics import mean_squared_error
training_error = mean_squared_error(y_train,model5.predict(X_train))
training_error

# %%
testing_error = mean_squared_error(y_test,y_pred5)
testing_error

# %%
from sklearn.model_selection import train_test_split
from sklearn.calibration import CalibratedClassifierCV
from sklearn.svm import LinearSVC
from sklearn.pipeline import make_pipeline
X_train, X_test, y_train, y_test = train_test_split(x_data,y_labels, test_size=0.4, random_state=42)

# %% [markdown]
# ## MODEL-6

# %%
model6 = make_pipeline(StandardScaler(),LinearSVC(random_state=60, tol=1e-5, max_iter=20000))

# %%
model6.fit(X_train, y_train)

# %%
print(model6.named_steps['linearsvc'].coef_)

# %%
print(model6.predict(X_test))

# %%
accuracy_score(y_test, model6.predict(X_test))

# %%
accuracy_score(y_train, model6.predict(X_train))

# %%
y_pred6=model6.predict(X_test)

# %%
cm = confusion_matrix(y_test, y_pred6)
cm

# %%
from sklearn.metrics import mean_squared_error
training_error = mean_squared_error(y_train,model6.predict(X_train))
training_error

# %%
testing_error = mean_squared_error(y_test,y_pred5)
testing_error

# %%
print(classification_report(y_test, y_pred6))

# %%
cm = confusion_matrix(y_test, y_pred6)
cm

# %% [markdown]
# ## ROC AUC Score and Curve

# %%
fpr1, tpr1, thresh1 = roc_curve(y_test1, pred_prob1[:,1],pos_label=1)
fpr2, tpr2, thresh2 = roc_curve(y_test2, pred_prob2[:,1], pos_label=1)
fpr3, tpr3, thresh3 = roc_curve(y_test3, pred_prob3[:,1], pos_label=1)
fpr4, tpr4, thresh4 = roc_curve(y_test4, pred_prob4[:,1], pos_label=1)
fpr5, tpr5, thresh5 = roc_curve(y_test5, pred_prob5[:,1], pos_label=1)
# roc curve for tpr = fpr 
random_probs = [0 for i in range(len(y_test))]
p_fpr, p_tpr, _ = roc_curve(y_test, random_probs, pos_label=1)


# %%
# auc scores
auc_score1 = roc_auc_score(y_test1, pred_prob1[:,1])
auc_score2 = roc_auc_score(y_test2, pred_prob2[:,1])
auc_score3 = roc_auc_score(y_test3, pred_prob3[:,1])
auc_score4 = roc_auc_score(y_test4, pred_prob4[:,1])
auc_score5 = roc_auc_score(y_test5, pred_prob5[:,1])


print(auc_score1, auc_score2,auc_score3,auc_score4,auc_score5)

# %%
plt.style.use('seaborn')

# plot roc curves
plt.plot(fpr1, tpr1, linestyle='--',color='orange', label='Logistic Regression')
plt.plot(fpr2, tpr2, linestyle='--',color='yellow', label='Random Forest')
plt.plot(fpr3, tpr3, linestyle='--',color='green', label='KNN')
plt.plot(fpr4, tpr4, linestyle='--',color='blue', label='Decision Tree')
plt.plot(fpr5, tpr5, linestyle='--',color='red', label='Gaussian')
plt.plot(p_fpr, p_tpr, linestyle='--', color='black')
plt.text(0.6, 0.21, 'AUC LR = %0.4f' % auc_score1, ha='center', fontsize=10, weight='bold', color='orange')
plt.text(0.6, 0.16, 'AUC RF = %0.4f' % auc_score2, ha='center', fontsize=10, weight='bold', color='yellow')
plt.text(0.6, 0.11, 'AUC KNN = %0.4f' % auc_score3, ha='center', fontsize=10, weight='bold', color='green')
plt.text(0.6, 0.05, 'AUC DT = %0.4f' % auc_score4, ha='center', fontsize=10, weight='bold', color='blue')
plt.text(0.6, 0.0, 'AUC Gau= %0.4f' % auc_score5, ha='center', fontsize=10, weight='bold', color='red')

# title
plt.title('ROC curve')
# x label
plt.xlabel('False Positive Rate')
# y label
plt.ylabel('True Positive rate')

plt.legend(loc='best')
plt.savefig('ROC',dpi=500)
plt.show();

# %% [markdown]
# ## Dataset 2

# %%
# Read Data 
df2 = pd.read_csv("/content/drive/MyDrive/Finalv3.csv")
df2

# %%
df2.isna().any()

# %%
df2 = df2.dropna()

# %%
df2=df2.drop("No.", axis='columns')
df2

# %%
df2.dataframeName = 'Final2.csv'

# %%
df2.isna().any()

# %%
y = df2['ABF']

# %%
plotCorrelationMatrix(df2, 10)

# %%
plotScatterMatrix(df2, 15, 10)

# %%
feature_set = ['Time','Source','Destination','Protocol','Length']

# %%
from sklearn.preprocessing import OrdinalEncoder
from sklearn.preprocessing import OneHotEncoder
le = OrdinalEncoder()
le.fit(df2)
cat_encoded = le.fit_transform(df2[feature_set[1:]])
print(type(cat_encoded), cat_encoded.shape)
cont_data = df2[feature_set[0]].to_numpy().reshape(-1,1) 
print(type(cont_data), cont_data.shape)
x_data = np.append(cat_encoded, cont_data, axis=1)
print(x_data.shape)
y_labels = df2['ABF']


from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(x_data, y_labels, test_size=0.4, random_state=42)

# %%
x_data

# %% [markdown]
# ## MODEL-1

# %%
model1=model1.fit(X_train,y_train)

# %%
from sklearn.metrics import accuracy_score
accuracy_score(y_test, model1.predict(X_test))

# %%
accuracy_score(y_train, model1.predict(X_train))

# %%
y_pred1  =  model1.predict(X_test)
y_pred1

# %%
cm = confusion_matrix(y_test, y_pred1)
cm

# %%
print(classification_report(y_test, y_pred1))

# %%
pred_prob1 = model1.predict_proba(X_test)
pred_prob1

# %%
y_test1=y_test

# %%
from sklearn.metrics import mean_squared_error
training_error = mean_squared_error(y_train,model1.predict(X_train))
training_error

# %%
testing_error = mean_squared_error(y_test,y_pred1)
testing_error

# %% [markdown]
# ## MODEL-2

# %%
model2=model2.fit(X_train,y_train)

# %%
y_pred2  =  model2.predict(X_test)
y_pred2

# %%
accuracy_score(y_test,  model2.predict(X_test))

# %%
accuracy_score(y_train, model2.predict(X_train))

# %%
from sklearn.metrics import classification_report
print(classification_report(y_test, y_pred2))

# %%
cm = confusion_matrix(y_test, y_pred2)
cm

# %%
from sklearn.metrics import mean_squared_error
training_error = mean_squared_error(y_train,model2.predict(X_train))
training_error

# %%
testing_error = mean_squared_error(y_test,y_pred2)
testing_error

# %%
pred_prob2 = model2.predict_proba(X_test)

# %%
y_test2=y_test

# %% [markdown]
# ## MODEL-3

# %%
model3 = model3.fit(X_train, y_train)

# %%
print(model3.predict(X_test))

# %%
y_pred3=model3.predict(X_test)
y_pred3

# %%
from numpy import unique
from numpy import where
# retrieve unique clusters
clusters = unique(y_pred3)
# create scatter plot for samples from each cluster
for cluster in clusters:
    row_ix = where(y_pred3 == cluster)
	# create scatter of these samples
    plt.scatter(X_test[row_ix, 0], X_test[row_ix, 1])
# show the plot
plt.show()

# %%
from sklearn.metrics import classification_report
print(classification_report(y_test, y_pred3))

# %%
accuracy_score(y_test, model3.predict(X_test))

# %%
accuracy_score(y_train, model3.predict(X_train))

# %%
cm = confusion_matrix(y_test, y_pred3)
cm

# %%
pred_prob3 = model3.predict_proba(X_test)

# %%
y_test3=y_test

# %% [markdown]
# ## MODEL-4

# %%
model4 = DecisionTreeClassifier(criterion='gini', splitter='best', max_depth=None, min_samples_split=2, 
                              min_samples_leaf=1, min_weight_fraction_leaf=0.0, max_features=5, random_state=50, max_leaf_nodes=None, 
                              min_impurity_decrease=0.0, class_weight=None, ccp_alpha=0.01)

# %%
model4=model4.fit(X_train, y_train)

# %%
y_pred4 = model4.predict(X_test)
y_pred4

# %%
accuracy_score(y_test, model4.predict(X_test))

# %%
accuracy_score(y_train, model4.predict(X_train))

# %%
print(classification_report(y_test, y_pred4))

# %%
pred_prob4 = model4.predict_proba(X_test)

# %%
y_test4=y_test

# %%
cm = confusion_matrix(y_test, y_pred4)
cm

# %%
from sklearn.metrics import mean_squared_error
training_error = mean_squared_error(y_train,model4.predict(X_train))
training_error

# %%
testing_error = mean_squared_error(y_test,y_pred4)
testing_error

# %% [markdown]
# ## MODEL-5

# %%
model5 = GaussianNB(priors=None, var_smoothing=1e-09)

# %%
model5=model5.fit(X_train, y_train)

# %%
y_pred5 = model5.predict(X_test)
y_pred5

# %%
accuracy_score(y_test, model5.predict(X_test))

# %%
accuracy_score(y_train, model5.predict(X_train))

# %%
from sklearn.metrics import mean_squared_error
training_error = mean_squared_error(y_train,model5.predict(X_train))
training_error

# %%
testing_error = mean_squared_error(y_test,y_pred5)
testing_error

# %%
print(classification_report(y_test, y_pred5))

# %%
pred_prob5 = model5.predict_proba(X_test)

# %%
y_test5=y_test

# %%
cm = confusion_matrix(y_test, y_pred5)
cm

# %% [markdown]
# ## MODEL-6

# %%
model6 = make_pipeline(StandardScaler(),LinearSVC(random_state=0, tol=1e-5))

# %%
model6.fit(X_train, y_train)

# %%
print(model6.named_steps['linearsvc'].coef_)

# %%
print(model6.predict(X_test))

# %%
y_pred6=model6.predict(X_test)
y_pred6

# %%
from sklearn.metrics import mean_squared_error
training_error = mean_squared_error(y_train,model6.predict(X_train))
training_error

# %%
testing_error = mean_squared_error(y_test,y_pred6)
testing_error

# %%
accuracy_score(y_test, model5.predict(X_test))

# %%
accuracy_score(y_train, model5.predict(X_train))

# %%
print(classification_report(y_test, y_pred6))

# %%
cm = confusion_matrix(y_test, y_pred6)
cm

# %% [markdown]
# ## AUC ROC Curve score and Graph

# %%
fpr1, tpr1, thresh1 = roc_curve(y_test1, pred_prob1[:,1],pos_label=1)
fpr2, tpr2, thresh2 = roc_curve(y_test2, pred_prob2[:,1], pos_label=1)
fpr3, tpr3, thresh3 = roc_curve(y_test3, pred_prob3[:,1], pos_label=1)
fpr4, tpr4, thresh4 = roc_curve(y_test4, pred_prob4[:,1], pos_label=1)
fpr5, tpr5, thresh5 = roc_curve(y_test5, pred_prob5[:,1], pos_label=1)

# roc curve for tpr = fpr 
random_probs = [0 for i in range(len(y_test))]
p_fpr, p_tpr, _ = roc_curve(y_test, random_probs, pos_label=1)


# %%
# auc scores
auc_score1 = roc_auc_score(y_test1, pred_prob1[:,1])
auc_score2 = roc_auc_score(y_test2, pred_prob2[:,1])
auc_score3 = roc_auc_score(y_test3, pred_prob3[:,1])
auc_score4 = roc_auc_score(y_test4, pred_prob4[:,1])
auc_score5 = roc_auc_score(y_test5, pred_prob5[:,1])


print(auc_score1, auc_score2,auc_score3,auc_score4,auc_score5)

# %%
plt.style.use('seaborn')

# plot roc curves
plt.plot(fpr1, tpr1, linestyle='--',color='orange', label='Logistic Regression')
plt.plot(fpr2, tpr2, linestyle='--',color='yellow', label='Random Forest')
plt.plot(fpr3, tpr3, linestyle='--',color='green', label='KNN')
plt.plot(fpr4, tpr4, linestyle='--',color='blue', label='Decision Tree')
plt.plot(fpr5, tpr5, linestyle='--',color='red', label='Gaussian')
plt.plot(p_fpr, p_tpr, linestyle='--', color='black')
plt.text(0.6, 0.21, 'AUC LR = %0.4f' % auc_score1, ha='center', fontsize=10, weight='bold', color='orange')
plt.text(0.6, 0.16, 'AUC RF = %0.4f' % auc_score2, ha='center', fontsize=10, weight='bold', color='yellow')
plt.text(0.6, 0.11, 'AUC KNN = %0.4f' % auc_score3, ha='center', fontsize=10, weight='bold', color='green')
plt.text(0.6, 0.05, 'AUC DT = %0.4f' % auc_score4, ha='center', fontsize=10, weight='bold', color='blue')
plt.text(0.6, 0.0, 'AUC Gau= %0.4f' % auc_score5, ha='center', fontsize=10, weight='bold', color='red')
# title
plt.title('ROC curve')
# x label
plt.xlabel('False Positive Rate')
# y label
plt.ylabel('True Positive rate')

plt.legend(loc='best')
plt.savefig('ROC',dpi=500)
plt.show();

# %% [markdown]
# # References

# %% [markdown]
# Scikit-learn.org. (2019). scikit-learn: machine learning in Python — scikit-learn 0.20.3 documentation. [online] Available at: https://scikit-learn.org/stable/index.html.
# 
# 
# GitHub. (n.d.). False review detection and model comparision · harshika14/CMPE-257_ProjectTeam12@0d25e01. [online] Available at: https://github.com/harshika14/CMPE-257_ProjectTeam12/commit/0d25e010a9387719c414b1589c74ebdfccc6678e?cv=1 [Accessed 1 June. 2022].
# 
# ‌
# BHANDARI, A. (2020). AUC-ROC Curve in Machine Learning Clearly Explained. [online] Analytics Vidhya. Available at: https://www.analyticsvidhya.com/blog/2020/06/auc-roc-curve-machine-learning/ [Accessed 1 June. 2022].
# 
# 
# Brownlee, J. (2020). 10 Clustering Algorithms With Python. [online] MachineLearningMastery.com. Available at: https://machinelearningmastery.com/clustering-algorithms-with-python/?cv=1&fbclid=IwAR3i9bv5u0l9gPN0FzJ2x3bl01IWJh8LfCQfGoZnFl-AmEY3HC0GGPldu-Q [Accessed 9 Jan. 2023].
# 
# ‌



import pandas as pd
import arff
import numpy as np
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
import joblib

# **************************************************************************************
# Load and preprocess dataset from ARFF file.
# **************************************************************************************
file = open("final-dataset.arff")
decoder = arff.ArffDecoder()
data = decoder.decode(file, encode_nominal=True)
print(data['data'][2])

# **************************************************************************************
# Extract features and labels from the dataset
# **************************************************************************************
vals = [val[0:-1] for val in data['data']]
labels = [lab[-1] for lab in data['data']]

# **************************************************************************************
# Data balancing: ensure each class has a sufficient number of samples.
# **************************************************************************************
da = set(labels)
brac = 600
templ = []
tempd = []
for i in da:
    count = 0
    while count < brac:
        for j in range(len(labels)):
            if labels[j]:
                templ.append(labels[j])
                tempd.append(vals[j])
                count += 1
            if count == brac:
                break
vals = tempd
labels = templ

l = len(vals)
print(l)

# **************************************************************************************
# Split the dataset into training and testing sets.
# **************************************************************************************
X_train, X_test, Y_train, Y_test = train_test_split(vals, labels, stratify=labels,test_size=0.2, random_state=0)

# **************************************************************************************
# Standardize the features for better model performance.
# **************************************************************************************
scaler = StandardScaler()
x_train = scaler.fit_transform(X_train)
x_test = scaler.transform(X_test)
y_train = np.array(Y_train)
y_test = np.array(Y_test)

# **************************************************************************************
# Train an SVM model and save it.
# **************************************************************************************
model = SVC(kernel='sigmoid', gamma='auto')
model.fit(x_train, y_train)

joblib.dump(model, 'model.joblib')
joblib.dump(scaler, 'scaler.joblib')

# **************************************************************************************
# Evaluate the model's performance on the test set.
# **************************************************************************************
y_pred = model.predict(x_test)
y_pred = pd.DataFrame(y_pred)
print((accuracy_score(y_test, y_pred))*100, '%')





# import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
# from sklearn.neighbors import KNNeighborsClassifier
# from sklearn.naive_bayes import GaussianNB
# from sklearn.ensemble import RandomForestClassifier
import liac_arff

# Load the dataset
file = open("final-dataset.arff")
decoder = liac_arff.ArffDecoder()
data = decoder.decode(file, encode_nominal=True)

vals = [val[0:-1] for val in data['data']]
labels = [lab[-1] for lab in data['data']]

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

X_train, X_test, Y_train, Y_test = train_test_split(vals, labels, stratify=labels,test_size=0.2, random_state=0)

scaler = StandardScaler()
x_train = scaler.fit_transform(X_train)
x_test = scaler.transform(X_test)
y_train = np.array(Y_train)
y_test = np.array(Y_test)

# SVM
model = SVC(kernal='sigmoid', gamma='auto')
model.fit(x_train, y_train)

y_pred = model.predict(x_test)
print((accuracy_score(y_test, y_pred))*100, '%')



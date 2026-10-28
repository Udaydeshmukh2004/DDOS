import hashlib
import sys
import sklearn
import pandas
import numpy
import scipy
import pytest

with open('data/authentic_insdn_leakage_free.csv', 'rb') as f:
    h = hashlib.sha256(f.read()).hexdigest()

print('authentic_insdn_leakage_free.csv SHA256:', h)
print('Python:', sys.version.replace('\n', ' '))
print('scikit-learn:', sklearn.__version__)
print('pandas:', pandas.__version__)
print('numpy:', numpy.__version__)
print('scipy:', scipy.__version__)
print('pytest:', pytest.__version__)


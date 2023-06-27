import matplotlib.pyplot as plt
import numpy as np

aesdata = []
with open("aes.txt", 'r') as file1:
    for line in file1:
        values = line.strip().split(',')
        for value in values:
            if len(value) > 0:
                aesdata.append(float(value))


rsadata = []
with open("rsa.txt", 'r') as file2:
    for line in file2:
        values = line.strip().split(',')
        for value in values:
            if len(value) > 0:
                rsadata.append(float(value))


x1 = range(len(aesdata))
x2 = range(len(rsadata))

plt.scatter(x1, aesdata, c = "blue", label = "aes", s = 10)
plt.scatter(x2, rsadata, c = "red", label = "rsa", s = 10)
plt.ylim(0, 100000)
plt.legend()

plt.show()
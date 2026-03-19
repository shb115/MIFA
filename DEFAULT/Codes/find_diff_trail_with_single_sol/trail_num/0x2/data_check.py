import pickle

with open("data_6r.pkl", "rb") as f:
    data = pickle.load(f)  

#print(data)
#print(sum(data)/len(data))
#print(len(data))
print("6r:",data.count(1)/len(data))

with open("data_7r.pkl", "rb") as f:
    data = pickle.load(f)  

#print(data)
#print(sum(data)/len(data))
#print(len(data))
print("7r:",data.count(1)/len(data))

with open("data_8r.pkl", "rb") as f:
    data = pickle.load(f)  

print(data)
#print(sum(data)/len(data))
#print(len(data))
print("8r:",data.count(1)/len(data))
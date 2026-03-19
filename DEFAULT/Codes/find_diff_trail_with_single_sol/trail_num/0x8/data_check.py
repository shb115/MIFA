import pickle

with open("data_8r.pkl", "rb") as f:
    data = pickle.load(f)

print(data)
#print(sum(data)/len(data))
#print(len(data))
print("8r:",data.count(1)/len(data))
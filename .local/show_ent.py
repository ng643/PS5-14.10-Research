import json
d = json.load(open(r"C:\PS5contrib\docs\dumps_13.60\sysent_index.json"))
e = d["entries"]
print("sysent_rva", hex(d["sysent_rva"]), "n", len(e))
for k in (0, 607, 629, 670, 673, 674, 675, 676, 677):
    print(k, e[k])

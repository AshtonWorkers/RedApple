function opt(a, b){ var s = 0; for (var i = 0; i < a.length; i++) s += a[i] * b; return s; }
var arr = [1.1, 2.2, 3.3];
for (var i = 0; i < 100000; i++) opt(arr, i);
opt({length: 3, 0: {}, 1: 2, 2: 3}, 1);
print("done");

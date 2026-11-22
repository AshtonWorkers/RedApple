var ab = new ArrayBuffer(0x1000);
var a = new Float64Array(ab);
for (var i = 0; i < a.length; i++) a[i] = i * 1.1;
a.sort(function(x, y){ a.length; return y - x; });
print(a[0]);

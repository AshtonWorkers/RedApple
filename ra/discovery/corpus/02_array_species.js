class E extends Array {}
var a = new E(10);
a.fill(1.1);
Object.defineProperty(a, 'length', { value: 0x10000, writable: true });
var b = a.concat(a, a);
print(b.length);

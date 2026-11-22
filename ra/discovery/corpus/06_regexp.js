var r = new RegExp("(a+)+$");
try { r.test("a".repeat(100) + "b"); } catch(e) {}
var s = "x".repeat(1e6);
print(s.replace(/x/g, "yy").length);

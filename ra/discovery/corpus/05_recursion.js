function f(x){ return f(x + 1) + f(x + 2); }
try { f(0); } catch(e) {}
var g = () => g();
try { g(); } catch(e) {}
print("done");

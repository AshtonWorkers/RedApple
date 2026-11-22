var target = [1, 2, 3];
var p = new Proxy(target, {
  get: function(t, k){ if (k === 'length') { t.length = 0; } return t[k]; }
});
Array.prototype.slice.call(p, 0, 100);
print("ok");

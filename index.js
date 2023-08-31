const name="SecureCaesar";let main=null;try{main=window??self}catch(t){main=global}async function Exporter(t,...r){var i=(0,(await import("node:module")).createRequire)("file:///"+(await import("path")).resolve(".").replaceAll("\\","/")),o={exports:{}};return t(o,o.exports,i),o.exports[r[0]](...r.slice(1))}Object.defineProperty(main,name,{writable:!1,configurable:!1,enumerable:!1,value:function(...t){return Exporter(function(N,I,L){"use strict";function t(t,r){return function(){return r||t((r={exports:{}}).exports,r),r.exports}}function o(t,r,i,o){if(r&&"object"==typeof r||"function"==typeof r)for(var e,n=F(r),s=0,h=n.length;s<h;s++)e=n[s],k.call(t,e)||e===i||u(t,e,{get:(function(t){return r[t]}).bind(null,e),enumerable:!(o=Z(r,e))||o.enumerable});return t}function r(t,r,i){return i=null!=t?P(K(t)):{},o(!r&&t&&t.__esModule?i:u(i,"default",{value:t,enumerable:!0}),t)}var i,e,n,s,h,P=Object.create,u=Object.defineProperty,Z=Object.getOwnPropertyDescriptor,F=Object.getOwnPropertyNames,K=Object.getPrototypeOf,k=Object.prototype.hasOwnProperty,f=t(function(t){t._=t._array_like_to_array=function(t,r){(null==r||r>t.length)&&(r=t.length);for(var i=0,o=new Array(r);i<r;i++)o[i]=t[i];return o}}),z=t(function(t){var r=f();t._=t._array_without_holes=function(t){if(Array.isArray(t))return r._(t)}}),U=t(function(t){t._=t._iterable_to_array=function(t){if("undefined"!=typeof Symbol&&null!=t[Symbol.iterator]||null!=t["@@iterator"])return Array.from(t)}}),G=t(function(t){t._=t._non_iterable_spread=function(){throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}}),$=t(function(t){var o=f();t._=t._unsupported_iterable_to_array=function(t,r){var i;if(t)return"string"==typeof t?o._(t,r):"Map"===(i="Object"===(i=Object.prototype.toString.call(t).slice(8,-1))&&t.constructor?t.constructor.name:i)||"Set"===i?Array.from(i):"Arguments"===i||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(i)?o._(t,r):void 0}}),a=t(function(t){var r=z(),i=U(),o=G(),e=$();t._=t._to_consumable_array=function(t){return r._(t)||i._(t)||e._(t)||o._()}}),p={},H=p,c={Decrypt:function(){return ot},Encrypt:function(){return it},Key:function(){return C}};for(i in c)u(H,i,{get:c[i],enumerable:!0});function l(){this.i=0,this.j=0,this.S=new Array}function m(){var t=(new Date).getTime();n[s++]^=255&t,n[s++]^=t>>8&255,n[s++]^=t>>16&255,n[s++]^=t>>24&255,256<=s&&(s-=256)}if(N.exports=o(u({},"__esModule",{value:!0}),p),l.prototype.init=function(t){for(var r,i,o=0;o<256;++o)this.S[o]=o;for(o=r=0;o<256;++o)r=r+this.S[o]+t[o%t.length]&255,i=this.S[o],this.S[o]=this.S[r],this.S[r]=i;this.i=0,this.j=0},l.prototype.next=function(){var t;return this.i=this.i+1&255,this.j=this.j+this.S[this.i]&255,t=this.S[this.i],this.S[this.i]=this.S[this.j],this.S[this.j]=t,this.S[t+this.S[this.i]&255]},null==n){for(n=new Array,s=0;s<256;)h=Math.floor(65536*Math.random()),n[s++]=h>>>8,n[s++]=255&h;s=0,m()}function y(){}function v(t,r){t=t.toString(),r=parseInt(r);var i,o=t.split("").map(function(t){return(t.charCodeAt(0)+r)%T}).map(function(t){for(;t<0;)t+=T;return t});return(i=String).fromCharCode.apply(i,(0,J._)(o))}y.prototype.nextBytes=function(t){for(var r=0;r<t.length;++r)t[r]=function(){if(null==e){for(m(),(e=new l).init(n),s=0;s<n.length;++s)n[s]=0;s=0}return e.next()}()};var J=r(a(),1),T=1e4,Q=r(a(),1);function d(t,r){var i=2<arguments.length&&void 0!==arguments[2]?arguments[2]:new y;null!=t&&("number"==typeof t?this.fromNumber(t,r,i):null==r&&"string"!=typeof t?this.fromString(t,256):this.fromString(t,r))}function g(){return new d(null)}function b(t,r,i,o,e,n){for(var s=16383&r,h=r>>14;0<=--n;){var u=16383&this[t],f=this[t++]>>14,a=h*u+f*s;e=((u=s*u+((16383&a)<<14)+i[o]+e)>>28)+(a>>14)+h*f,i[o++]=268435455&u}return e}p="undefined"==typeof navigator?(d.prototype.am=b,28):navigator&&"Microsoft Internet Explorer"==navigator.appName?(d.prototype.am=function(t,r,i,o,e,n){for(var s=32767&r,h=r>>15;0<=--n;){var u=32767&this[t],f=this[t++]>>15,a=h*u+f*s;e=((u=s*u+((32767&a)<<15)+i[o]+(1073741823&e))>>>30)+(a>>>15)+h*f+(e>>>30),i[o++]=1073741823&u}return e},30):navigator&&"Netscape"!=navigator.appName?(d.prototype.am=function(t,r,i,o,e,n){for(;0<=--n;){var s=r*this[t++]+i[o]+e;e=Math.floor(s/67108864),i[o++]=67108863&s}return e},26):(d.prototype.am=b,28),d.prototype.DB=p,d.prototype.DM=(1<<p)-1,d.prototype.DV=1<<p,d.prototype.FV=Math.pow(2,52),d.prototype.F1=52-p,d.prototype.F2=2*p-52;for(var S=new Array,D="0".charCodeAt(0),B=0;B<=9;++B)S[D++]=B;for(D="a".charCodeAt(0),B=10;B<36;++B)S[D++]=B;for(D="A".charCodeAt(0),B=10;B<36;++B)S[D++]=B;function w(t){return"0123456789abcdefghijklmnopqrstuvwxyz".charAt(t)}function M(t,r){var i=S[t.charCodeAt(r)];return null==i?-1:i}function E(t){var r=g();return r.fromInt(t),r}function O(t){var r,i=1;return 0!=(r=t>>>16)&&(t=r,i+=16),0!=(r=t>>8)&&(t=r,i+=8),0!=(r=t>>4)&&(t=r,i+=4),0!=(r=t>>2)&&(t=r,i+=2),0!=(r=t>>1)&&(t=r,i+=1),i}function _(t){this.m=t}function A(t){this.m=t,this.mp=t.invDigit(),this.mpl=32767&this.mp,this.mph=this.mp>>15,this.um=(1<<t.DB-15)-1,this.mt2=2*t.t}function W(t,r){return t&r}function R(t,r){return t|r}function x(t,r){return t^r}function X(t,r){return t&~r}function q(){}function Y(t){return t}function V(t){this.r2=g(),this.q3=g(),d.ONE.dlShiftTo(2*t.t,this.r2),this.mu=this.r2.divide(t),this.m=t}_.prototype.convert=function(t){return t.s<0||0<=t.compareTo(this.m)?t.mod(this.m):t},_.prototype.revert=function(t){return t},_.prototype.reduce=function(t){t.divRemTo(this.m,null,t)},_.prototype.mulTo=function(t,r,i){t.multiplyTo(r,i),this.reduce(i)},_.prototype.sqrTo=function(t,r){t.squareTo(r),this.reduce(r)},A.prototype.convert=function(t){var r=g();return t.abs().dlShiftTo(this.m.t,r),r.divRemTo(this.m,null,r),t.s<0&&0<r.compareTo(d.ZERO)&&this.m.subTo(r,r),r},A.prototype.revert=function(t){var r=g();return t.copyTo(r),this.reduce(r),r},A.prototype.reduce=function(t){for(;t.t<=this.mt2;)t[t.t++]=0;for(var r=0;r<this.m.t;++r){var i=32767&t[r],o=i*this.mpl+((i*this.mph+(t[r]>>15)*this.mpl&this.um)<<15)&t.DM;for(t[i=r+this.m.t]+=this.m.am(0,o,t,r,0,this.m.t);t[i]>=t.DV;)t[i]-=t.DV,t[++i]++}t.clamp(),t.drShiftTo(this.m.t,t),0<=t.compareTo(this.m)&&t.subTo(this.m,t)},A.prototype.mulTo=function(t,r,i){t.multiplyTo(r,i),this.reduce(i)},A.prototype.sqrTo=function(t,r){t.squareTo(r),this.reduce(r)},d.prototype.copyTo=function(t){for(var r=this.t-1;0<=r;--r)t[r]=this[r];t.t=this.t,t.s=this.s},d.prototype.fromInt=function(t){this.t=1,this.s=t<0?-1:0,0<t?this[0]=t:t<-1?this[0]=t+this.DV:this.t=0},d.prototype.fromString=function(t,r){var i;if(16==r)i=4;else if(8==r)i=3;else if(256==r)i=8;else if(2==r)i=1;else if(32==r)i=5;else{if(4!=r)return void this.fromRadix(t,r);i=2}this.t=0,this.s=0;for(var o=t.length,e=!1,n=0;0<=--o;){var s=8==i?255&t[o]:M(t,o);s<0?"-"==t.charAt(o)&&(e=!0):(e=!1,0==n?this[this.t++]=s:n+i>this.DB?(this[this.t-1]|=(s&(1<<this.DB-n)-1)<<n,this[this.t++]=s>>this.DB-n):this[this.t-1]|=s<<n,(n+=i)>=this.DB&&(n-=this.DB))}8==i&&128&t[0]&&(this.s=-1,0<n)&&(this[this.t-1]|=(1<<this.DB-n)-1<<n),this.clamp(),e&&d.ZERO.subTo(this,this)},d.prototype.clamp=function(){for(var t=this.s&this.DM;0<this.t&&this[this.t-1]==t;)--this.t},d.prototype.dlShiftTo=function(t,r){for(var i=this.t-1;0<=i;--i)r[i+t]=this[i];for(i=t-1;0<=i;--i)r[i]=0;r.t=this.t+t,r.s=this.s},d.prototype.drShiftTo=function(t,r){for(var i=t;i<this.t;++i)r[i-t]=this[i];r.t=Math.max(this.t-t,0),r.s=this.s},d.prototype.lShiftTo=function(t,r){for(var i=t%this.DB,o=this.DB-i,e=(1<<o)-1,n=Math.floor(t/this.DB),s=this.s<<i&this.DM,h=this.t-1;0<=h;--h)r[h+n+1]=this[h]>>o|s,s=(this[h]&e)<<i;for(h=n-1;0<=h;--h)r[h]=0;r[n]=s,r.t=this.t+n+1,r.s=this.s,r.clamp()},d.prototype.rShiftTo=function(t,r){r.s=this.s;var i=Math.floor(t/this.DB);if(i>=this.t)r.t=0;else{var o=t%this.DB,e=this.DB-o,n=(1<<o)-1;r[0]=this[i]>>o;for(var s=i+1;s<this.t;++s)r[s-i-1]|=(this[s]&n)<<e,r[s-i]=this[s]>>o;0<o&&(r[this.t-i-1]|=(this.s&n)<<e),r.t=this.t-i,r.clamp()}},d.prototype.subTo=function(t,r){for(var i=0,o=0,e=Math.min(t.t,this.t);i<e;)o+=this[i]-t[i],r[i++]=o&this.DM,o>>=this.DB;if(t.t<this.t){for(o-=t.s;i<this.t;)o+=this[i],r[i++]=o&this.DM,o>>=this.DB;o+=this.s}else{for(o+=this.s;i<t.t;)o-=t[i],r[i++]=o&this.DM,o>>=this.DB;o-=t.s}r.s=o<0?-1:0,o<-1?r[i++]=this.DV+o:0<o&&(r[i++]=o),r.t=i,r.clamp()},d.prototype.multiplyTo=function(t,r){var i=this.abs(),o=t.abs(),e=i.t;for(r.t=e+o.t;0<=--e;)r[e]=0;for(e=0;e<o.t;++e)r[e+i.t]=i.am(0,o[e],r,e,0,i.t);r.s=0,r.clamp(),this.s!=t.s&&d.ZERO.subTo(r,r)},d.prototype.squareTo=function(t){for(var r=this.abs(),i=t.t=2*r.t;0<=--i;)t[i]=0;for(i=0;i<r.t-1;++i){var o=r.am(i,r[i],t,2*i,0,1);(t[i+r.t]+=r.am(i+1,2*r[i],t,2*i+1,o,r.t-i-1))>=r.DV&&(t[i+r.t]-=r.DV,t[i+r.t+1]=1)}0<t.t&&(t[t.t-1]+=r.am(i,r[i],t,2*i,0,1)),t.s=0,t.clamp()},d.prototype.divRemTo=function(t,r,i){if(!((a=t.abs()).t<=0)){var o=this.abs();if(o.t<a.t)null!=r&&r.fromInt(0),null!=i&&this.copyTo(i);else{null==i&&(i=g());var e=g(),n=this.s,s=t.s,h=this.DB-O(a[a.t-1]),u=(0<h?(a.lShiftTo(h,e),o.lShiftTo(h,i)):(a.copyTo(e),o.copyTo(i)),e.t),f=e[u-1];if(0!=f){var a=f*(1<<this.F1)+(1<u?e[u-2]>>this.F2:0),p=this.FV/a,c=(1<<this.F1)/a,l=1<<this.F2,m=i.t,y=m-u,v=null==r?g():r;for(e.dlShiftTo(y,v),0<=i.compareTo(v)&&(i[i.t++]=1,i.subTo(v,i)),d.ONE.dlShiftTo(u,v),v.subTo(e,e);e.t<u;)e[e.t++]=0;for(;0<=--y;){var T=i[--m]==f?this.DM:Math.floor(i[m]*p+(i[m-1]+l)*c);if((i[m]+=e.am(0,T,i,y,0,u))<T)for(e.dlShiftTo(y,v),i.subTo(v,i);i[m]<--T;)i.subTo(v,i)}null!=r&&(i.drShiftTo(u,r),n!=s)&&d.ZERO.subTo(r,r),i.t=u,i.clamp(),0<h&&i.rShiftTo(h,i),n<0&&d.ZERO.subTo(i,i)}}}},d.prototype.invDigit=function(){var t,r;return!(this.t<1)&&1&(t=this[0])?0<(r=(r=(r=(r=(r=3&t)*(2-(15&t)*r)&15)*(2-(255&t)*r)&255)*(2-((65535&t)*r&65535))&65535)*(2-t*r%this.DV)%this.DV)?this.DV-r:-r:0},d.prototype.isEven=function(){return 0==(0<this.t?1&this[0]:this.s)},d.prototype.exp=function(t,r){if(4294967295<t||t<1)return d.ONE;var i,o=g(),e=g(),n=r.convert(this),s=O(t)-1;for(n.copyTo(o);0<=--s;)r.sqrTo(o,e),0<(t&1<<s)?r.mulTo(e,n,o):(i=o,o=e,e=i);return r.revert(o)},d.prototype.toString=function(t){if(this.s<0)return"-"+this.negate().toString(t);var r;if(16==t)r=4;else if(8==t)r=3;else if(2==t)r=1;else if(32==t)r=5;else{if(4!=t)return this.toRadix(t);r=2}var i,o=(1<<r)-1,e=!1,n="",s=this.t,h=this.DB-s*this.DB%r;if(0<s--)for(h<this.DB&&0<(i=this[s]>>h)&&(e=!0,n=w(i));0<=s;)h<r?(i=(this[s]&(1<<h)-1)<<r-h,i|=this[--s]>>(h+=this.DB-r)):(i=this[s]>>(h-=r)&o,h<=0&&(h+=this.DB,--s)),(e=0<i||e)&&(n+=w(i));return e?n:"0"},d.prototype.negate=function(){var t=g();return d.ZERO.subTo(this,t),t},d.prototype.abs=function(){return this.s<0?this.negate():this},d.prototype.compareTo=function(t){var r=this.s-t.s;if(0!=r)return r;var i=this.t;if(0!=(r=i-t.t))return this.s<0?-r:r;for(;0<=--i;)if(0!=(r=this[i]-t[i]))return r;return 0},d.prototype.bitLength=function(){return this.t<=0?0:this.DB*(this.t-1)+O(this[this.t-1]^this.s&this.DM)},d.prototype.mod=function(t){var r=g();return this.abs().divRemTo(t,null,r),this.s<0&&0<r.compareTo(d.ZERO)&&t.subTo(r,r),r},d.prototype.modPowInt=function(t,r){var i=new(t<256||r.isEven()?_:A)(r);return this.exp(t,i)},d.ZERO=E(0),d.ONE=E(1),q.prototype.convert=Y,q.prototype.revert=Y,q.prototype.mulTo=function(t,r,i){t.multiplyTo(r,i)},q.prototype.sqrTo=function(t,r){t.squareTo(r)},V.prototype.convert=function(t){var r;return t.s<0||t.t>2*this.m.t?t.mod(this.m):t.compareTo(this.m)<0?t:(r=g(),t.copyTo(r),this.reduce(r),r)},V.prototype.revert=function(t){return t},V.prototype.reduce=function(t){for(t.drShiftTo(this.m.t-1,this.r2),t.t>this.m.t+1&&(t.t=this.m.t+1,t.clamp()),this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3),this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);t.compareTo(this.r2)<0;)t.dAddOffset(1,this.m.t+1);for(t.subTo(this.r2,t);0<=t.compareTo(this.m);)t.subTo(this.m,t)},V.prototype.mulTo=function(t,r,i){t.multiplyTo(r,i),this.reduce(i)},V.prototype.sqrTo=function(t,r){t.squareTo(r),this.reduce(r)};var j=[2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997],tt=(1<<26)/j[j.length-1],rt=(d.prototype.chunkSize=function(t){return Math.floor(Math.LN2*this.DB/Math.log(t))},d.prototype.toRadix=function(t){if(null==t&&(t=10),0==this.signum()||t<2||36<t)return"0";var r=this.chunkSize(t),i=Math.pow(t,r),o=E(i),e=g(),n=g(),s="";for(this.divRemTo(o,e,n);0<e.signum();)s=(i+n.intValue()).toString(t).substr(1)+s,e.divRemTo(o,e,n);return n.intValue().toString(t)+s},d.prototype.fromRadix=function(t,r){this.fromInt(0);for(var i=this.chunkSize(r=null==r?10:r),o=Math.pow(r,i),e=!1,n=0,s=0,h=0;h<t.length;++h){var u=M(t,h);u<0?"-"==t.charAt(h)&&0==this.signum()&&(e=!0):(s=r*s+u,++n>=i&&(this.dMultiply(o),this.dAddOffset(s,0),s=n=0))}0<n&&(this.dMultiply(Math.pow(r,n)),this.dAddOffset(s,0)),e&&d.ZERO.subTo(this,this)},d.prototype.fromNumber=function(t,r,i){if("number"==typeof r)if(t<2)this.fromInt(1);else for(this.fromNumber(t,i),this.testBit(t-1)||this.bitwiseTo(d.ONE.shiftLeft(t-1),R,this),this.isEven()&&this.dAddOffset(1,0);!this.isProbablePrime(r);)this.dAddOffset(2,0),this.bitLength()>t&&this.subTo(d.ONE.shiftLeft(t-1),this);else{var o=new Array,e=7&t;o.length=1+(t>>3),r.nextBytes(o),0<e?o[0]&=(1<<e)-1:o[0]=0,this.fromString(o,256)}},d.prototype.bitwiseTo=function(t,r,i){for(var o,e=Math.min(t.t,this.t),n=0;n<e;++n)i[n]=r(this[n],t[n]);if(t.t<this.t){for(o=t.s&this.DM,n=e;n<this.t;++n)i[n]=r(this[n],o);i.t=this.t}else{for(o=this.s&this.DM,n=e;n<t.t;++n)i[n]=r(o,t[n]);i.t=t.t}i.s=r(this.s,t.s),i.clamp()},d.prototype.changeBit=function(t,r){var i=d.ONE.shiftLeft(t);return this.bitwiseTo(i,r,i),i},d.prototype.addTo=function(t,r){for(var i=0,o=0,e=Math.min(t.t,this.t);i<e;)o+=this[i]+t[i],r[i++]=o&this.DM,o>>=this.DB;if(t.t<this.t){for(o+=t.s;i<this.t;)o+=this[i],r[i++]=o&this.DM,o>>=this.DB;o+=this.s}else{for(o+=this.s;i<t.t;)o+=t[i],r[i++]=o&this.DM,o>>=this.DB;o+=t.s}r.s=o<0?-1:0,0<o?r[i++]=o:o<-1&&(r[i++]=this.DV+o),r.t=i,r.clamp()},d.prototype.dMultiply=function(t){this[this.t]=this.am(0,t-1,this,0,0,this.t),++this.t,this.clamp()},d.prototype.dAddOffset=function(t,r){if(0!=t){for(;this.t<=r;)this[this.t++]=0;for(this[r]+=t;this[r]>=this.DV;)this[r]-=this.DV,++r>=this.t&&(this[this.t++]=0),++this[r]}},d.prototype.multiplyLowerTo=function(t,r,i){var o,e=Math.min(this.t+t.t,r);for(i.s=0,i.t=e;0<e;)i[--e]=0;for(o=i.t-this.t;e<o;++e)i[e+this.t]=this.am(0,t[e],i,e,0,this.t);for(o=Math.min(t.t,r);e<o;++e)this.am(0,t[e],i,e,0,r-e);i.clamp()},d.prototype.multiplyUpperTo=function(t,r,i){var o=i.t=this.t+t.t- --r;for(i.s=0;0<=--o;)i[o]=0;for(o=Math.max(r-this.t,0);o<t.t;++o)i[this.t+o-r]=this.am(r-o,t[o],i,0,0,this.t+o-r);i.clamp(),i.drShiftTo(1,i)},d.prototype.modInt=function(t){if(t<=0)return 0;var r=this.DV%t,i=this.s<0?t-1:0;if(0<this.t)if(0==r)i=this[0]%t;else for(var o=this.t-1;0<=o;--o)i=(r*i+this[o])%t;return i},d.prototype.millerRabin=function(t){var r=this.subtract(d.ONE),i=r.getLowestSetBit();if(i<=0)return!1;var o=r.shiftRight(i);j.length<(t=t+1>>1)&&(t=j.length);for(var e=g(),n=0;n<t;++n){e.fromInt(j[Math.floor(Math.random()*j.length)]);var s=e.modPow(o,this);if(0!=s.compareTo(d.ONE)&&0!=s.compareTo(r)){for(var h=1;h++<i&&0!=s.compareTo(r);)if(0==(s=s.modPowInt(2,this)).compareTo(d.ONE))return!1;if(0!=s.compareTo(r))return!1}}return!0},d.prototype.clone=function(){var t=g();return this.copyTo(t),t},d.prototype.intValue=function(){if(this.s<0){if(1==this.t)return this[0]-this.DV;if(0==this.t)return-1}else{if(1==this.t)return this[0];if(0==this.t)return 0}return(this[1]&(1<<32-this.DB)-1)<<this.DB|this[0]},d.prototype.byteValue=function(){return 0==this.t?this.s:this[0]<<24>>24},d.prototype.shortValue=function(){return 0==this.t?this.s:this[0]<<16>>16},d.prototype.signum=function(){return this.s<0?-1:this.t<=0||1==this.t&&this[0]<=0?0:1},d.prototype.toByteArray=function(){var t,r=this.t,i=new Array,o=(i[0]=this.s,this.DB-r*this.DB%8),e=0;if(0<r--)for(o<this.DB&&(t=this[r]>>o)!=(this.s&this.DM)>>o&&(i[e++]=t|this.s<<this.DB-o);0<=r;)o<8?(t=(this[r]&(1<<o)-1)<<8-o,t|=this[--r]>>(o+=this.DB-8)):(t=this[r]>>(o-=8)&255,o<=0&&(o+=this.DB,--r)),128&t&&(t|=-256),0==e&&(128&this.s)!=(128&t)&&++e,(0<e||t!=this.s)&&(i[e++]=t);return i},d.prototype.equals=function(t){return 0==this.compareTo(t)},d.prototype.min=function(t){return this.compareTo(t)<0?this:t},d.prototype.max=function(t){return 0<this.compareTo(t)?this:t},d.prototype.and=function(t){var r=g();return this.bitwiseTo(t,W,r),r},d.prototype.or=function(t){var r=g();return this.bitwiseTo(t,R,r),r},d.prototype.xor=function(t){var r=g();return this.bitwiseTo(t,x,r),r},d.prototype.andNot=function(t){var r=g();return this.bitwiseTo(t,X,r),r},d.prototype.not=function(){for(var t=g(),r=0;r<this.t;++r)t[r]=this.DM&~this[r];return t.t=this.t,t.s=~this.s,t},d.prototype.shiftLeft=function(t){var r=g();return t<0?this.rShiftTo(-t,r):this.lShiftTo(t,r),r},d.prototype.shiftRight=function(t){var r=g();return t<0?this.lShiftTo(-t,r):this.rShiftTo(t,r),r},d.prototype.getLowestSetBit=function(){for(var t,r,i=0;i<this.t;++i)if(0!=this[i])return i*this.DB+(r=void 0,0==(t=this[i])?-1:(r=0,65535&t||(t>>=16,r+=16),255&t||(t>>=8,r+=8),15&t||(t>>=4,r+=4),3&t||(t>>=2,r+=2),1&t||++r,r));return this.s<0?this.t*this.DB:-1},d.prototype.bitCount=function(){for(var t=0,r=this.s&this.DM,i=0;i<this.t;++i)t+=function(t){for(var r=0;0!=t;)t&=t-1,++r;return r}(this[i]^r);return t},d.prototype.testBit=function(t){var r=Math.floor(t/this.DB);return r>=this.t?0!=this.s:0!=(this[r]&1<<t%this.DB)},d.prototype.setBit=function(t){return this.changeBit(t,R)},d.prototype.clearBit=function(t){return this.changeBit(t,X)},d.prototype.flipBit=function(t){return this.changeBit(t,x)},d.prototype.add=function(t){var r=g();return this.addTo(t,r),r},d.prototype.subtract=function(t){var r=g();return this.subTo(t,r),r},d.prototype.multiply=function(t){var r=g();return this.multiplyTo(t,r),r},d.prototype.divide=function(t){var r=g();return this.divRemTo(t,r,null),r},d.prototype.remainder=function(t){var r=g();return this.divRemTo(t,null,r),r},d.prototype.divideAndRemainder=function(t){var r=g(),i=g();return this.divRemTo(t,r,i),new Array(r,i)},d.prototype.modPow=function(t,r){var i=t.bitLength(),o=E(1);if(i<=0)return o;var e=i<18?1:i<48?3:i<144?4:i<768?5:6,n=new(i<8?_:r.isEven()?V:A)(r),s=new Array,h=3,u=e-1,f=(1<<e)-1;if(s[1]=n.convert(this),1<e){var a=g();for(n.sqrTo(s[1],a);h<=f;)s[h]=g(),n.mulTo(a,s[h-2],s[h]),h+=2}for(var p,c,l=t.t-1,m=!0,y=g(),i=O(t[l])-1;0<=l;){for(u<=i?p=t[l]>>i-u&f:(p=(t[l]&(1<<i+1)-1)<<u-i,0<l&&(p|=t[l-1]>>this.DB+i-u)),h=e;!(1&p);)p>>=1,--h;if((i-=h)<0&&(i+=this.DB,--l),m)s[p].copyTo(o),m=!1;else{for(;1<h;)n.sqrTo(o,y),n.sqrTo(y,o),h-=2;0<h?n.sqrTo(o,y):(c=o,o=y,y=c),n.mulTo(y,s[p],o)}for(;0<=l&&!(t[l]&1<<i);)n.sqrTo(o,y),c=o,o=y,y=c,--i<0&&(i=this.DB-1,--l)}return n.revert(o)},d.prototype.modInverse=function(t){var r=t.isEven();if(this.isEven()&&r||0==t.signum())return d.ZERO;for(var i=t.clone(),o=this.clone(),e=E(1),n=E(0),s=E(0),h=E(1);0!=i.signum();){for(;i.isEven();)i.rShiftTo(1,i),r?(e.isEven()&&n.isEven()||(e.addTo(this,e),n.subTo(t,n)),e.rShiftTo(1,e)):n.isEven()||n.subTo(t,n),n.rShiftTo(1,n);for(;o.isEven();)o.rShiftTo(1,o),r?(s.isEven()&&h.isEven()||(s.addTo(this,s),h.subTo(t,h)),s.rShiftTo(1,s)):h.isEven()||h.subTo(t,h),h.rShiftTo(1,h);0<=i.compareTo(o)?(i.subTo(o,i),r&&e.subTo(s,e),n.subTo(h,n)):(o.subTo(i,o),r&&s.subTo(e,s),h.subTo(n,h))}return 0!=o.compareTo(d.ONE)?d.ZERO:0<=h.compareTo(t)?h.subtract(t):h.signum()<0&&(h.addTo(t,h),h.signum()<0)?h.add(t):h},d.prototype.pow=function(t){return this.exp(t,new q)},d.prototype.gcd=function(t){var r=this.s<0?this.negate():this.clone(),i=t.s<0?t.negate():t.clone(),o=(r.compareTo(i)<0&&(e=r,r=i,i=e),r.getLowestSetBit()),e=i.getLowestSetBit();if(e<0)return r;for(0<(e=o<e?o:e)&&(r.rShiftTo(e,r),i.rShiftTo(e,i));0<r.signum();)0<(o=r.getLowestSetBit())&&r.rShiftTo(o,r),0<(o=i.getLowestSetBit())&&i.rShiftTo(o,i),0<=r.compareTo(i)?(r.subTo(i,r),r.rShiftTo(1,r)):(i.subTo(r,i),i.rShiftTo(1,i));return 0<e&&i.lShiftTo(e,i),i},d.prototype.isProbablePrime=function(t){var r,i=this.abs();if(1==i.t&&i[0]<=j[j.length-1]){for(r=0;r<j.length;++r)if(i[0]==j[r])return!0;return!1}if(i.isEven())return!1;for(r=1;r<j.length;){for(var o=j[r],e=r+1;e<j.length&&o<tt;)o*=j[e++];for(o=i.modInt(o);r<e;)if(o%j[r++]==0)return!1}return i.millerRabin(t)},d.prototype.square=function(){var t=g();return this.squareTo(t),t},T.toString().length-1),C=function(){var t=0<arguments.length&&void 0!==arguments[0]?arguments[0]:1,r="K";t*=32;for(var i=0;i<t;i++)r+=function(t,r){for(t=t.toString();t.length<r;)t="0"+t;return t}(function(t){var r=0<arguments.length?t:0;if(15<r)throw new Error("Generated random number is too big");var i=new y,o=(r<1&&(i.nextBytes(r=[0]),r=r[0]%15+1),"0".repeat(r).split(""));return i.nextBytes(o),parseInt(parseInt(o.join("")).toString().slice(0,r))}(rt),rt);return r},it=function(t){var r=1<arguments.length&&void 0!==arguments[1]?arguments[1]:0,i=2<arguments.length&&void 0!==arguments[2]&&arguments[2];if(i&&"string"!=typeof r)throw new Error("Error: Key must be a string");t=(t=function(t,r){var i=1<arguments.length&&void 0!==r?r:this.n.bitLength()+7>>3,o=!(2<arguments.length);if(i<t.length+11)return console.log("Message is too long"),null;for(var e=new Array,n=t.length-1;0<=n&&0<i;){var s=t.charCodeAt(n--);s<128?e[--i]=s:127<s&&s<2048?(e[--i]=63&s|128,e[--i]=s>>6|192):(e[--i]=63&s|128,e[--i]=s>>6&63|128,e[--i]=s>>12|224)}e[--i]=0;for(var h=new y,u=new Array;2<i;){for(u[0]=0;0==u[0];)h.nextBytes(u);e[--i]=u[0]}return e[--i]=2,e[--i]=0,o?new d(e):(o=String).fromCharCode.apply(o,(0,Q._)(e))}(t.toString(),function(t){for(var r=32;r<t.length;)r+=32;return r+32}(t),!1)).split("");for(var o=null,o=(!i&&r<1?C(t.length/32):i?r.toString():C(r)).replace(/^K/,""),e=0;e<t.length;e++){var n=4*e%(o.length-1),n=o.slice(n,4+n);t[e]=v(t[e],n)}return{key:"K"+o,cipher:t.join("")}},ot=function(t,r){if("string"!=typeof r)throw new Error("Error: Key must be a string");r=r.replace(/^K/,""),t=t.toString().split("");for(var i=0;i<t.length;i++){var o=4*i%(r.length-1),o=parseInt(r.slice(o,4+o));t[i]=v(t[i],-o)}var e=t.join("");return function(t,r){for(var i=1<arguments.length&&void 0!==r?r:this.n.bitLength()+7>>3,o=null,o=(2<arguments.length?o=new d(o=t.split("").map(function(t){return t.charCodeAt(0)})):t).toByteArray(),e=0;e<o.length&&0==o[e];)++e;if(o.length-e!=i-1||2!=o[e])return null;for(++e;0!=o[e];)if(++e>=o.length)return null;for(var n="";++e<o.length;){var s=255&o[e];s<128?n+=String.fromCharCode(s):191<s&&s<224?(n+=String.fromCharCode((31&s)<<6|63&o[e+1]),++e):(n+=String.fromCharCode((15&s)<<12|(63&o[e+1])<<6|63&o[e+2]),e+=2)}return n}(e,e.length,!1)}},...t)}});
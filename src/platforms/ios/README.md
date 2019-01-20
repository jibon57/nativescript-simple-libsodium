`sodium.a` file has been compiled from "https://github.com/jedisct1/libsodium". Version: 1.0.17

If you would like to update the version then you can download source code from that repo & complie by yourself.

Note: During use your own compiled file you may face problem like this issue: https://github.com/NativeScript/ios-runtime/issues/1061
In this case you will need to follow the procedures as described there.


`nm --defined-only sodium.a | grep " T " | cut -f 3 -d' ' | egrep -v '^$|sodium\.a'`


Optional command: `comm -23 <(sort defined.txt) <(sort noneed.txt) > sodium_defined.txt`
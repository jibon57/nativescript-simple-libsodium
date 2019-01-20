var SimpleLibsodium = require("nativescript-simple-libsodium").SimpleLibsodium;
var simpleLibsodium = new SimpleLibsodium();

describe("greet function", function() {
    it("exists", function() {
        expect(simpleLibsodium.greet).toBeDefined();
    });

    it("returns a string", function() {
        expect(simpleLibsodium.greet()).toEqual("Hello, NS");
    });
});
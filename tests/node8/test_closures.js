function makeCounter(start) {
    var count = start;
    return function() {
        count = count + 1;
        return count;
    };
}

function makeAdder(x) {
    return function(y) {
        return x + y;
    };
}

function applyTwice(fn, val) {
    return fn(fn(val));
}

function compose(f, g) {
    return function(x) {
        return f(g(x));
    };
}

var counter = makeCounter(0);
console.log(counter());
console.log(counter());

var add5 = makeAdder(5);
console.log(add5(3));

console.log(applyTwice(add5, 10));

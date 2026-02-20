// =============================================
// Comprehensive test: many features in one file
// =============================================

// --- Arithmetic & Math ---
function lerp(a, b, t) {
    return a + (b - a) * t;
}

function distance(x1, y1, x2, y2) {
    var dx = x2 - x1;
    var dy = y2 - y1;
    return Math.sqrt(dx * dx + dy * dy);
}

function fibonacci(n) {
    var a = 0, b = 1;
    for (var i = 0; i < n; i++) {
        var temp = b;
        b = a + b;
        a = temp;
    }
    return a;
}

function gcd(a, b) {
    while (b !== 0) {
        var temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

function isPrime(n) {
    if (n < 2) return false;
    for (var i = 2; i * i <= n; i++) {
        if (n % i === 0) return false;
    }
    return true;
}

// --- Array operations ---
function map(arr, fn) {
    var result = [];
    for (var i = 0; i < arr.length; i++) {
        result.push(fn(arr[i], i));
    }
    return result;
}

function filter(arr, fn) {
    var result = [];
    for (var i = 0; i < arr.length; i++) {
        if (fn(arr[i])) {
            result.push(arr[i]);
        }
    }
    return result;
}

function reduce(arr, fn, initial) {
    var acc = initial;
    for (var i = 0; i < arr.length; i++) {
        acc = fn(acc, arr[i]);
    }
    return acc;
}

function flatten(arr) {
    var result = [];
    for (var i = 0; i < arr.length; i++) {
        if (Array.isArray(arr[i])) {
            var sub = flatten(arr[i]);
            for (var j = 0; j < sub.length; j++) {
                result.push(sub[j]);
            }
        } else {
            result.push(arr[i]);
        }
    }
    return result;
}

function binarySearch(arr, target) {
    var lo = 0;
    var hi = arr.length - 1;
    while (lo <= hi) {
        var mid = (lo + hi) >> 1;
        if (arr[mid] === target) return mid;
        if (arr[mid] < target) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return -1;
}

// --- String operations ---
function padLeft(str, len, ch) {
    while (str.length < len) {
        str = ch + str;
    }
    return str;
}

function words(str) {
    return str.split(" ");
}

function camelCase(str) {
    var parts = str.split("_");
    var result = parts[0];
    for (var i = 1; i < parts.length; i++) {
        result = result + parts[i][0].toUpperCase() + parts[i].slice(1);
    }
    return result;
}

// --- Object operations ---
function merge(obj1, obj2) {
    var result = {};
    var keys1 = Object.keys(obj1);
    for (var i = 0; i < keys1.length; i++) {
        result[keys1[i]] = obj1[keys1[i]];
    }
    var keys2 = Object.keys(obj2);
    for (var j = 0; j < keys2.length; j++) {
        result[keys2[j]] = obj2[keys2[j]];
    }
    return result;
}

function pick(obj, keys) {
    var result = {};
    for (var i = 0; i < keys.length; i++) {
        if (obj[keys[i]] !== undefined) {
            result[keys[i]] = obj[keys[i]];
        }
    }
    return result;
}

// --- Control flow patterns ---
function fizzbuzzList(n) {
    var result = [];
    for (var i = 1; i <= n; i++) {
        if (i % 15 === 0) {
            result.push("FizzBuzz");
        } else if (i % 3 === 0) {
            result.push("Fizz");
        } else if (i % 5 === 0) {
            result.push("Buzz");
        } else {
            result.push(i);
        }
    }
    return result;
}

function range(start, end, step) {
    if (step === undefined) step = 1;
    var result = [];
    for (var i = start; i < end; i = i + step) {
        result.push(i);
    }
    return result;
}

// --- Closures & higher-order ---
function memoize(fn) {
    var cache = {};
    return function(arg) {
        if (cache[arg] !== undefined) {
            return cache[arg];
        }
        var result = fn(arg);
        cache[arg] = result;
        return result;
    };
}

function curry(fn) {
    return function(a) {
        return function(b) {
            return fn(a, b);
        };
    };
}

function once(fn) {
    var called = false;
    var result;
    return function() {
        if (!called) {
            result = fn();
            called = true;
        }
        return result;
    };
}

// --- Error handling ---
function safeGet(obj, path) {
    var parts = path.split(".");
    var current = obj;
    for (var i = 0; i < parts.length; i++) {
        if (current === null || current === undefined) {
            return undefined;
        }
        current = current[parts[i]];
    }
    return current;
}

function retry(fn, times) {
    var lastError;
    for (var i = 0; i < times; i++) {
        try {
            return fn();
        } catch (e) {
            lastError = e;
        }
    }
    throw lastError;
}

// --- Run some tests ---
console.log("lerp:", lerp(0, 10, 0.5));
console.log("distance:", distance(0, 0, 3, 4));
console.log("fib(10):", fibonacci(10));
console.log("gcd:", gcd(48, 18));
console.log("isPrime(17):", isPrime(17));
console.log("isPrime(15):", isPrime(15));

var nums = [1, 2, 3, 4, 5];
console.log("map:", map(nums, function(x) { return x * 2; }));
console.log("filter:", filter(nums, function(x) { return x > 2; }));
console.log("reduce:", reduce(nums, function(a, b) { return a + b; }, 0));
console.log("binarySearch:", binarySearch(nums, 3));

console.log("padLeft:", padLeft("42", 5, "0"));
console.log("camelCase:", camelCase("hello_world_foo"));

console.log("fizzbuzz:", fizzbuzzList(15));
console.log("range:", range(0, 10, 2));

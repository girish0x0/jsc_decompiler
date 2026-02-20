function safeDivide(a, b) {
    if (b === 0) {
        throw new Error("Division by zero");
    }
    return a / b;
}

function tryParse(str) {
    try {
        var result = JSON.parse(str);
        return result;
    } catch (e) {
        console.log("Parse error: " + e.message);
        return null;
    }
}

function withFinally(val) {
    try {
        if (val < 0) throw new Error("negative");
        return val * 2;
    } catch (e) {
        return -1;
    } finally {
        console.log("done");
    }
}

console.log(safeDivide(10, 3));
console.log(tryParse('{"a":1}'));
console.log(tryParse('bad json'));
console.log(withFinally(5));
console.log(withFinally(-1));

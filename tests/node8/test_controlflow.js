function abs(x) {
    if (x < 0) {
        return -x;
    }
    return x;
}

function max3(a, b, c) {
    if (a >= b && a >= c) return a;
    if (b >= c) return b;
    return c;
}

function countdown(n) {
    while (n > 0) {
        console.log(n);
        n = n - 1;
    }
    console.log("Done!");
}

function sumRange(start, end) {
    var sum = 0;
    for (var i = start; i <= end; i++) {
        sum = sum + i;
    }
    return sum;
}

function classify(score) {
    if (score >= 90) return "A";
    if (score >= 80) return "B";
    if (score >= 70) return "C";
    if (score >= 60) return "D";
    return "F";
}

console.log(abs(-5));
console.log(max3(10, 20, 15));
countdown(3);
console.log(sumRange(1, 100));
console.log(classify(85));

function greet(name) {
    return "Hello, " + name + "!";
}

function factorial(n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

function fizzbuzz(n) {
    for (var i = 1; i <= n; i++) {
        if (i % 15 === 0) {
            console.log("FizzBuzz");
        } else if (i % 3 === 0) {
            console.log("Fizz");
        } else if (i % 5 === 0) {
            console.log("Buzz");
        } else {
            console.log(i);
        }
    }
}

function sumArray(arr) {
    var total = 0;
    for (var i = 0; i < arr.length; i++) {
        total = total + arr[i];
    }
    return total;
}

console.log(greet("World"));
console.log(factorial(5));
fizzbuzz(15);
console.log(sumArray([1, 2, 3, 4, 5]));

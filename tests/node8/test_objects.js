function makeUser(name, age) {
    var user = {
        name: name,
        age: age,
        isAdult: age >= 18
    };
    return user;
}

function getFullName(first, last) {
    return first + " " + last;
}

function clamp(val, min, max) {
    if (val < min) return min;
    if (val > max) return max;
    return val;
}

function reverseString(str) {
    var result = "";
    for (var i = str.length - 1; i >= 0; i--) {
        result = result + str[i];
    }
    return result;
}

var u = makeUser("Alice", 25);
console.log(u.name, u.isAdult);
console.log(getFullName("John", "Doe"));
console.log(clamp(150, 0, 100));
console.log(reverseString("hello"));

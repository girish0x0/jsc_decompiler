function repeat(str, times) {
    var result = "";
    for (var i = 0; i < times; i++) {
        result = result + str;
    }
    return result;
}

function isPalindrome(str) {
    var len = str.length;
    for (var i = 0; i < len / 2; i++) {
        if (str[i] !== str[len - 1 - i]) {
            return false;
        }
    }
    return true;
}

function capitalize(str) {
    return str[0].toUpperCase() + str.slice(1);
}

function contains(haystack, needle) {
    return haystack.indexOf(needle) !== -1;
}

console.log(repeat("ab", 3));
console.log(isPalindrome("racecar"));
console.log(isPalindrome("hello"));
console.log(capitalize("hello"));
console.log(contains("hello world", "world"));

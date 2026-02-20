var vm = require('vm');
var fs = require('fs');
var path = require('path');

var files = ['test_basic.js', 'test_objects.js', 'test_controlflow.js', 'test_strings.js', 'test_closures.js', 'test_trycatch.js', 'test_big.js'];

files.forEach(function(file) {
    var src = fs.readFileSync(path.join(__dirname, file), 'utf8');
    var script = new vm.Script(src, {
        filename: file,
        produceCachedData: true
    });
    var outFile = file.replace('.js', '.jsc');
    fs.writeFileSync(path.join(__dirname, outFile), script.cachedData);
    console.log('Compiled ' + file + ' -> ' + outFile + ' (' + script.cachedData.length + ' bytes)');
});

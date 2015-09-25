#!/usr/bin/env node

var P = require('bluebird');
var fs = P.promisifyAll(require('fs'));
var VError = require('verror');
var path = require('path');
var homedir = require('home-or-tmp');
var BloomFilter = require('bloom-filter');
var mkdirp = P.promisify(require('mkdirp'));
var requisition = require('requisition');
var zlib = require('zlib');
var tar = require('tar');
var bl = require('bl');
var fstream = require('fstream');

var dir = process.argv[2] || '.';

fs.statAsync(dir).tap(assertIsDir).then(function () {
    return processDir(dir);
}).catch(function (err) {
    console.warn(err.message);
    process.exit(1);
});


function assertIsDir(stat) {
    if (!stat.isDirectory()) {
        throw new VError("%s is not a directory", dir);
    }
}

function processDir(dir) {
    return identifyWordpress(dir).then(loadWordpressBloomFilter).then(scanDir(dir)).then(console.log);
}

function identifyWordpress(dir) {
    return fs.readFileAsync(path.resolve(dir, 'wp-includes', 'version.php'), 'utf-8').then(function (versionFile) {
        var m = /wp_version = '(.*)'/.exec(versionFile);
        if (m) {
            return m[1];
        } else {
            throw new VError("Can't identify wordpress version in '%s'", dir);
        }
    });
}

function loadWordpressBloomFilter(version) {
    return fs.readFileAsync(path.resolve(homedir, '.config', 'wpsec', wpVersionBloomFile(version)), 'utf-8').then(function (data) {
        return new BloomFilter(JSON.parse(data));
    }).catch(function (err) {
        if (err.code == 'ENOENT') {
            return createFilter(wpVersionURL(version));
        } else {
            throw err;
        }
    });
}

function createFilter(url) {
    var filter = BloomFilter.create(16384, 0.01);
    var config = path.resolve(homedir, '.config', 'wpsec');
    return requisition(url).then(function (res) {
        return new P(function (y, n) {
            var s = res.pipe(zlib.createGunzip()).pipe(tar.Parse());
            s.on('error', n);
            s.on('end', y)
            s.on('entry', function (ent) {
                ent.pipe(bl(function (err, data) {
                    filter.insert(data);
                }));
            });
        });
    }).then(function () {
        return mkdirp(config);
    }).then(function () {
        return fs.writeFileAsync(path.resolve(config, encodeURIComponent(url) + '.bloom'), JSON.stringify(filter.toObject()));
    }).then(function () {
        return filter;
    });
}

function wpVersionURL(version) {
    return 'https://wordpress.org/wordpress-' + version + '.tar.gz'
}

function wpVersionBloomFile(version) {
    return encodeURIComponent(wpVersionURL(version)) + '.bloom';
}

function scanDir(dir) {
    return function (filter) {
        return new P(function(y, n) {
            var list = [];
            fstream.Reader({
                path: dir,
                type: "Directory"
            }).on('entry', handleEnt).on('error', n).on('end', function () {
                y(list);
            });

            function handleEnt(ent) {
                ent.on('entry', handleEnt);
                ent.pipe(bl(function (err, data) {
                    if (!filter.contains(data)) {
                        list.push(ent.props.path);
                    }
                }));
            }
        });
    };
}

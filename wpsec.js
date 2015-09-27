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
var unzip = require('unzip2');
var bl = require('bl');
var fstream = require('fstream');
var debug = require('debuglog')('wpsec');
var crypto = require('crypto');

function sha(d) {
    return crypto.createHash('sha1').update(d).digest('hex');
}

var command = process.argv[2];

if (command != 'scan') {
    help();
    process.exit(1);
}

var dir = process.argv[3] || '.';

scan(dir).catch(function (err) {
    console.warn(err.stack);
    process.exit(1);
});

function scan(dir) {
    return P.join(identifyWordpress(dir).then(loadWordpressBloomFilter), openDir(dir)).spread(filterDir).then(function (list) {
        list.forEach(function (e) {
            console.log(e);
        });
    });
}

function identifyWordpress(dir) {
    return fs.readFileAsync(path.resolve(dir, 'wp-includes', 'version.php'), 'utf-8').then(function (versionFile) {
        var m = /wp_version = '(.*)'/m.exec(versionFile);
        if (m) {
            return m[1];
        } else {
            throw new VError("Can't identify wordpress version in '%s'", dir);
        }
    });
}

function loadWordpressBloomFilter(version) {
    return getBloomFilter(wpVersionURL(version));
}

function loadAddonBloomFilter(kind, plugin, version) {
    return getBloomFilter(wpAddonUrl(kind, plugin, version));
}

function getBloomFilter(url) {
    var file = path.resolve(homedir, '.config', 'wpsec', bloomFile(url));
    return fs.readFileAsync(file).then(function (data) {
        debug("Loaded bloom filter %s", file);
        return new BloomFilter(JSON.parse(data));
    }).catch(function (err) {
        if (err.code == 'ENOENT') {
            return createFilter(url);
        } else {
            throw err;
        }
    }).then(function (filter) {
        return {
            url: url,
            filter: filter
        };
    });
}

function createFilter(url) {
    var filter = BloomFilter.create(16384, 0.01);
    var config = path.resolve(homedir, '.config', 'wpsec');
    debug('fetch', url);
    return requisition(url).then(function (res) {
        var s = /\.zip$/.test(url) ? res.pipe(unzip.Parse()) : res.pipe(zlib.createGunzip()).pipe(tar.Parse());
        s.on('entry', function (ent) {
            if (ent.type == 'File') {
                debug("%s '%s'", ent.type, ent.path);
                ent.pipe(bl(function (err, data) {
                    debug("Hashing %s bytes, sha1 '%s'", data.length, sha(data));
                    filter.insert(data);
                }));
            } else {
                ent.autodrain();
            }
        });

        return new P(function (y, n) {
            s.on('error', n);
            s.on('end', y)
            s.on('close', y)
            s.on('finish', y)
        });
    }).then(function () {
        debug('make config dir', config);
        return mkdirp(config);
    }).then(function () {
        var file = path.resolve(config, bloomFile(url));
        debug('write bloom filter', file);
        return fs.writeFileAsync(file, JSON.stringify(filter.toObject()));
    }).then(function () {
        return filter;
    });
}

function bloomFile(url) {
    return encodeURIComponent(url) + '.bloom';
}

function wpVersionURL(version) {
    return 'https://wordpress.org/wordpress-' + version + '.tar.gz'
}

function wpAddonUrl(kind, which, version) {
    return 'https://downloads.wordpress.org/' + kind +'/' + which + '.' + version + '.zip';
}

function openDir(dir) {
    var reader = fstream.Reader({
        path: dir,
        type: "Directory"
    });

    reader.pause();

    return reader;
}

function filterDir(filter, ent, fallback) {
    ent.pause();
    return new P(function (y, n) {
        var list = [];
        var waiting = [];

        if (ent.type == 'Directory') {
            if (!fallback && ent.depth == 3 && ent.parent.props.basename == 'plugins' && ent.parent.parent.props.basename == 'wp-content') {
                waiting.push(handleAddonDir('plugin', ent).catch(handleErrorAndFallback));
            } else if (!fallback && ent.depth == 3 && ent.parent.props.basename == 'themes' && ent.parent.parent.props.basename == 'wp-content') {
                waiting.push(handleAddonDir('theme', ent).catch(handleErrorAndFallback));
            } else if (!fallback && ent.depth == 2 && ent.props.basename == 'uploads' && ent.parent.props.basename == 'wp-content') {
                debug("uploads dir '%s', not scanning", ent.path);
                ent.resume();
            } else {
                debug("regular dir '%s'", ent.path);
                ent.resume();
                ent.on('entry', function (ent) {
                    waiting.push(filterDir(filter, ent));
                });
            }

            ent.on('end', function () {
                Promise.all(waiting).then(function (subs) {
                    subs.forEach(function (e) {
                        list = list.concat(e);
                    });
                    debug("ending '%s' with list of %s entries", ent.path, list.length);
                    y(list);
                }).catch(n);
            });

        } else if (ent.type == 'File') {
            ent.resume();
            ent.pipe(bl(function (err, data) {
                if (!filter.filter.contains(data)) {
                    debug("Suspect file '%s' detected using '%s' sha '%s'", ent.path, filter.url, sha(data));
                    y([ent.path]);
                }
            }));
        } else {
            ent.disown();
        }

        ent.on('error', n);
    });

    function handleErrorAndFallback(err) {
        console.warn(err.stack || err);
        return filterDir(filter, ent, true);
    }
}

function handleAddonDir(kind, ent) {
    debug(kind, 'dir', ent.path);
    var metadataFile = kind == 'plugin' ? ent.props.basename + '.php' : 'style.css';
    return fs.readFileAsync(path.resolve(ent.path, metadataFile), 'utf-8').then(function (metadata) {
        var m = /Version: (.*)$/m.exec(metadata);
        if (m) {
            return m[1];
        } else {
            throw new VError("No metadata found in '%s'", ent.path);
        }
    }).then(function (version) {
        return loadAddonBloomFilter(kind, ent.props.basename, version);
    }).then(function (filter) {
        return filterDir(filter, ent, true);
    });
}

function help() {
    console.warn("Use:", process.argv[0], process.argv[1], "scan", "[dir]");
}

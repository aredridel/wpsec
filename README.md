Wordpress Verifier
==================

A simple tool to verify wordpress installation and look for modified files.

Use
----

```
wpsec /path/to/wordpress
```

Will print a list of files that differ from the Wordpress distribution that is currently installed in that directory.

Caveats
-------

Does not know about plugins or themes yet.

Shows uploads as unknown files as well.


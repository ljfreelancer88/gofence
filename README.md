# GoFence - A CLI-Based Alternative to Wordfence
GoFence is a command-line utility that offers a powerful alternative to Wordfence. This tool is designed to provide efficient and resource-conscious solutions for safeguarding your web assets without the overhead of a graphical user interface.

## Key Motivation:
Wordfence, while effective, often consumes substantial resources in shared hosting environments due to its per-site utilization. In such scenarios, GoFence steps in as a streamlined and optimized solution, allowing you to proactively secure and manage web assets without straining server resources.

## How to use it?
### Install the companion
```cmd
git clone git@github.com:VirusTotal/yara.git
cd yara/
YACC=bison ./configure
make
```
### Scan your root web directory
`yara.log` filename is important. GoFence will look for this.
And the `wordpress.yara` is a set of rules for Yara
```cmd
$ yara -rs ./wordpress.yara /var/www > yara.log
```
### Run GoFence
Run GoFence and do some clean up.
```
/var/www$ ./gofence

Delete wp-includes/php-compat/good.php? [y/n]: n
Delete wp-includes/php-compat/bad.php? [y/n]: y
2023/08/15 15:17:15 Deleted wp-includes/php-compat/bad.php

```
## Room for Improvement:
GoFence is an evolving project with ongoing development. While it already provides a resource-efficient solution, there's still room for further enhancements and features. Your contributions and feedback are welcomed as we work together to refine and expand GoFence's capabilities.

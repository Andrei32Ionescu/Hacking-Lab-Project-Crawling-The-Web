# Hacking-Lab-Project-Crawling-The-Web

Web crawler implementation attempt using the Colly library

Reads the domains from the `top-1m.csv` file

```sh
go run crawler.go
```

For more options, enter

```sh
go run crawler.go --help
```

example

```sh
go run crawler.go -mode=title -concurrency=16 -file="cloudflare2000.csv" -depth=1
```

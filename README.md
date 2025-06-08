# Hacking-Lab-Project-Crawling-The-Web

Web crawler implementation attempt using the Colly library

Reads the domains from the `top-1m.csv` file and saves the results in the `results` file

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

Results of full scan for Apache web-server version of top-1m domains:
- https://tud365-my.sharepoint.com/:f:/g/personal/ajosan_tudelft_nl/EqimrSVMJdRCns0dJMZXVo0BYqQQD1ZvWI_5I3BGvJc-ww?e=dejLhS

or:
- https://filesender.surf.nl/?s=download&token=ffb94003-df3c-4b5f-b1d1-913b311b9980

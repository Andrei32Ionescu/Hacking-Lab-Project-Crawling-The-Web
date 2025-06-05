# Hacking-Lab-Project-Crawling-The-Web

Web crawler implementation attempt using the Colly library

It supports crawling for:
- website titles
- any statically loaded JavaScript files
- wordpress plugin and theme versions
- common security misconfigurations
- Wix websites
- Apache (Tomcat) servers

## Installation

Make sure to have go-lang version 1.23 or higher installed

## Running the crawler

Running the program with no flags, reads the domains from the `datasets/top-1m.csv` file, crawles for website titles with no concurrency and saves the results in the `results` file.

```sh
go run crawler.go
```

For more options, enter:

```sh
go run crawler.go --help
```

For example, when crawling for wordpress websites from a list of indexed domains, you might run the following command:

```sh
go run crawler.go -mode=wordpress -concurrency=16 -file="cloudflare2000.csv" -depth=1
```

## Running with Docker

You can build and run the crawler using Docker:

```sh
# Build the Docker image
# (run this in the go-colly directory)
docker build -t go-colly-crawler .

# Run the crawler (default options)
docker run --rm go-colly-crawler

# Pass arguments (example)
docker run --rm go-colly-crawler -mode=wordpress -concurrency=16 -file="cloudflare2000.csv" -depth=1 -console
```

The `datasets` folder is included in the image by default.

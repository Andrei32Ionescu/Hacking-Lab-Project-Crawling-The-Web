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

## Running with Docker

You can build and run the crawler using Docker:

```sh
# Build the Docker image
# (run this in the go-colly directory)
docker build -t go-colly-crawler .

# Run the crawler (default options)
docker run --rm go-colly-crawler

# Pass arguments (example)
docker run --rm go-colly-crawler -mode=title -concurrency=16 -file="datasets/cloudflare2000.csv" -depth=1

# Or, in two separate terminals:
docker run --rm go-colly-crawler -mode=wordpress -concurrency=20 -file="cloudflare2000.csv" -console
docker run --rm go-colly-crawler -mode=wordpress -concurrency=20 -file="top-2k.csv" -indexed -console
```

The `datasets` folder and `top-1m.csv` are included in the image by default. If you want to use your own input/output files, you can mount a local folder:

```sh
docker run --rm -v $(pwd)/datasets:/app/datasets go-colly-crawler -file="datasets/cloudflare2000.csv"
```

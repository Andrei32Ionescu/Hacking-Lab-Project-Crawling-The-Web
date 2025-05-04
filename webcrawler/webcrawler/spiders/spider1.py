import scrapy

#Spider class
class QuotesSpider(scrapy.Spider):
        #name of your spider
        name = "quotes"

        def start_requests(self):
                #Website links to crawl
                urls = [
                        'http://quotes.toscrape.com/page/1/',
                        'http://quotes.toscrape.com/page/2/',
                ]

                #loop through the urls
                for url in urls:
                        yield scrapy.Request(url=url, callback=self.parse)

        def parse(self, response):
                for quote in response.css('div.quote'):
                        yield {
                                'text': quote.css('span::text').get(),
                                'author': quote.css('small.author::text').get(),
                                'tags': quote.css('div.tags a.tag::text').getall()
                        }

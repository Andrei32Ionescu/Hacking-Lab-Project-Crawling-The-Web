# Hacking-Lab-Project-Crawling-The-Web

A Playwright-based crawler that aims to achieve 10-12 crawls per second. 

Currently, the three different crawler exist for testing purposes. The main crawler implementation is located in:
`src/crawler/main.py`
# Installation
1. Clone the repository:
   ```bash
   git clone <url>
2. Navigate to the project directory:
   ```bash
   cd Hacking-Lab-Project-Crawling-The-Web/python_crawlers
   ```
3. Install the required dependencies:
   ```bash
    pip install playwright
    playwright install
    ```
4. Run the crawler:
   ```bash
   python3 main.py
   ```
# Usage
Currently, the crawler is set to crawl a list of URLs defined in `src/crawler/urls.txt`. You can modify this file to add or remove URLs as needed.

Additionally, you can adjust the number of browsers, timeouts and concurrency settings in the `src/crawler/main.py` file to suit your requirements.
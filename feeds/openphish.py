'''Implements a provider for the OpenPhish free phishing feed.'''
import hashlib
import requests

from feeds.feed import Feed, FetchException
from models import Phish

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By


class OpenphishFeed(Feed):
    '''Implements a provider for the OpenPhish free phishing feed.'''

    def __init__(self):
        '''Creates a new instance of the OpenPhish feed.'''
        self.feed = 'openphish'
        self.url = "https://openphish.com/index.html"
        
    def _process_rows(self, rows):
        '''
        Processes new phishing entries from the OpenPhish feed.

        Every line is simply a URL for a phishing site. We need to
        check for existence and create the `models.Phish` entry to use for storage.

        For the OpenPhish feed, the PID is simply the hash of the URL.

        Args:
            rows {list[str]} - The rows to process
        '''
        entries = []
        urls_seen = []
        for url in rows: 
            if Phish.clean_url(url) in urls_seen:
                continue
            url_hash = hashlib.sha1()
            url_hash.update(url.encode("utf-8"))
            urls_seen.append(Phish.clean_url(url))
            entries.append(
                Phish(pid=url_hash.hexdigest(), url=url, feed=self.feed))
        return entries


    def get(self, offset=0):
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
        driver.get(self.url)
        urls = driver.find_elements(By.XPATH, '//td[@class = "url_entry"]')
        for i in range(0, len(urls)):
            urls[i] = urls[i].text
        
        return self._process_rows(urls)
